use std::ops::Range;

use crate::fingerprint::{FingerprintTable, Insert, fingerprint};
use crate::ledger::{CommitKind, CommitOutcome, Ledger, Proposal, StageStats};
use crate::wsnorm::normalize_into;

use super::templ::Forms;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Work {
    pub compares: u64,
    pub verifications: u64,
    pub scanned: u64,
}

pub struct Scratch {
    arena: Vec<u8>,
    line: Vec<u8>,
    norm: Vec<Option<Range<usize>>>,
    ids: Vec<Option<usize>>,
    coarse: Vec<Option<usize>>,
    work: Work,
    degraded: bool,
}

impl Default for Scratch {
    fn default() -> Self {
        Self::new()
    }
}

impl Scratch {
    pub fn new() -> Self {
        Self {
            arena: Vec::new(),
            line: Vec::new(),
            norm: Vec::new(),
            ids: Vec::new(),
            coarse: Vec::new(),
            work: Work::default(),
            degraded: false,
        }
    }

    pub fn with_capacity(span_bytes: usize, unit_bytes: usize) -> Self {
        Self {
            arena: Vec::with_capacity(span_bytes),
            line: Vec::with_capacity(unit_bytes),
            ..Self::new()
        }
    }

    pub fn reserved(&self) -> (usize, usize) {
        (self.arena.capacity(), self.line.capacity())
    }

    pub fn work(&self) -> Work {
        self.work
    }

    pub fn degraded(&self) -> bool {
        self.degraded
    }
}

pub fn repeated_blocks(
    span: &[u8],
    forms: Option<&Forms>,
    ledger: &mut Ledger<'_>,
    min_block_lines: u32,
    max_block_lines: u32,
    scratch: &mut Scratch,
) -> StageStats {
    if !load(span, forms, ledger, scratch) {
        scratch.degraded = true;
        return StageStats::default();
    }
    let min = min_block_lines.max(1) as usize;
    let max = max_block_lines.max(1) as usize;
    let mut same_bytes = |first: usize, second: usize, len: usize| {
        block(&scratch.norm, &scratch.arena, first, len)
            == block(&scratch.norm, &scratch.arena, second, len)
    };
    let mut left_wall =
        |before: usize, first: usize| forms.is_some_and(|forms| forms.same(before, first));
    let mut coarse_same =
        |first: usize, second: usize| forms.is_some_and(|forms| forms.same(first, second));
    let mut domain = Domain {
        ids: &scratch.ids,
        same_bytes: &mut same_bytes,
        left_wall: &mut left_wall,
        coarse_ids: &scratch.coarse,
        coarse_same: &mut coarse_same,
    };
    windowed_blocks(
        ledger,
        &mut domain,
        min,
        max,
        CommitKind::Block,
        &mut scratch.work,
    )
}

fn load(span: &[u8], forms: Option<&Forms>, ledger: &Ledger<'_>, scratch: &mut Scratch) -> bool {
    let units = ledger.units();
    scratch.arena.clear();
    scratch.line.clear();
    reset(scratch, units.len());
    scratch.work = Work::default();
    scratch.degraded = false;
    let mut table = FingerprintTable::for_keys(span.len());
    for (index, unit) in units.iter().enumerate() {
        if !unit.eligible || ledger.is_committed(index) {
            continue;
        }
        normalize_into(&span[unit.range.clone()], &mut scratch.line);
        let start = scratch.arena.len();
        let hash = fingerprint(&scratch.line);
        scratch.arena.extend_from_slice(&scratch.line);
        let range = start..scratch.arena.len();
        let rep = match table.insert_hashed(&scratch.arena, range.clone(), index, hash) {
            Insert::New => index,
            Insert::Duplicate(rep) => rep,
            Insert::Full => {
                reset(scratch, units.len());
                return false;
            }
        };
        scratch.norm[index] = Some(range);
        scratch.ids[index] = Some(rep);
        scratch.coarse[index] = Some(match forms {
            Some(forms) => forms.id(index).0 as usize,
            None => rep,
        });
    }
    true
}

fn reset(scratch: &mut Scratch, units: usize) {
    scratch.norm.clear();
    scratch.norm.resize(units, None);
    for column in [&mut scratch.ids, &mut scratch.coarse] {
        column.clear();
        column.resize(units, None);
    }
}

fn block<'a>(
    norm: &'a [Option<Range<usize>>],
    arena: &'a [u8],
    start: usize,
    len: usize,
) -> &'a [u8] {
    let first = norm[start]
        .as_ref()
        .expect("candidate members are residual");
    let last = norm[start + len - 1]
        .as_ref()
        .expect("candidate members are residual");
    &arena[first.start..last.end]
}

pub(crate) struct Domain<'a, S, W, C> {
    pub ids: &'a [Option<usize>],
    pub same_bytes: S,
    pub left_wall: W,
    pub coarse_ids: &'a [Option<usize>],
    pub coarse_same: C,
}

pub(crate) fn windowed_blocks<
    S: FnMut(usize, usize, usize) -> bool,
    W: FnMut(usize, usize) -> bool,
    C: FnMut(usize, usize) -> bool,
>(
    ledger: &mut Ledger<'_>,
    domain: &mut Domain<'_, S, W, C>,
    min_block_lines: usize,
    max_block_lines: usize,
    kind: CommitKind,
    work: &mut Work,
) -> StageStats {
    let ids = domain.ids;
    let min = min_block_lines.max(1);
    let max = max_block_lines.max(1);
    let mut stats = StageStats::default();
    let mut at = 0;
    let mut run = 0;
    while at < ids.len() {
        run = run.max(at);
        while run < ids.len() && !ledger.is_committed(run) && ids[run].is_some() {
            work.scanned += 1;
            run += 1;
        }
        let room = run - at;
        let mut next = at + 1;
        let mut length = max.min(room / 2);
        while length >= min {
            if equal(ids, at, at + length, length, work) {
                work.verifications += 1;
                if (domain.same_bytes)(at, at + length, length)
                    && anchor_is_match_free(domain, at, length, work)
                {
                    if wall_blocks(ledger, domain, at) {
                        break;
                    }
                    let copies = copies(ids, at, length, room, &mut domain.same_bytes, work);
                    let group = at..at + copies * length;
                    if let CommitOutcome::Committed(commit) =
                        ledger.try_commit(Proposal::repeat(group.clone(), length, kind))
                    {
                        stats.bump(commit.kind);
                        next = group.end;
                    }
                    break;
                }
            }
            length -= 1;
        }
        at = next;
    }
    stats
}

fn wall_blocks<S, W, C>(ledger: &Ledger<'_>, domain: &mut Domain<'_, S, W, C>, at: usize) -> bool
where
    S: FnMut(usize, usize, usize) -> bool,
    W: FnMut(usize, usize) -> bool,
    C: FnMut(usize, usize) -> bool,
{
    at > 0
        && !ledger.is_committed(at - 1)
        && domain.ids[at - 1].is_some()
        && (domain.left_wall)(at - 1, at)
}

fn anchor_is_match_free<S, W, C>(
    domain: &mut Domain<'_, S, W, C>,
    at: usize,
    length: usize,
    work: &mut Work,
) -> bool
where
    S: FnMut(usize, usize, usize) -> bool,
    W: FnMut(usize, usize) -> bool,
    C: FnMut(usize, usize) -> bool,
{
    let ids = domain.coarse_ids;
    let end = at + length;
    let mut period = (end - at) / 2;
    while period > 0 {
        let mut start = at;
        while start + 2 * period <= end {
            if equal(ids, start, start + period, period, work)
                && (domain.coarse_same)(start, start + period)
            {
                work.verifications += 1;
                return false;
            }
            start += 1;
        }
        period -= 1;
    }
    true
}

fn equal(ids: &[Option<usize>], first: usize, second: usize, len: usize, work: &mut Work) -> bool {
    for at in 0..len {
        work.compares += 1;
        if ids[first + at] != ids[second + at] {
            return false;
        }
    }
    true
}

fn copies(
    ids: &[Option<usize>],
    at: usize,
    length: usize,
    room: usize,
    same_bytes: &mut impl FnMut(usize, usize, usize) -> bool,
    work: &mut Work,
) -> usize {
    let mut copies = 2;
    while (copies + 1) * length <= room {
        let first = at + (copies - 1) * length;
        let second = first + length;
        if !equal(ids, first, second, length, work) {
            break;
        }
        work.verifications += 1;
        if !same_bytes(first, second, length) {
            break;
        }
        copies += 1;
    }
    copies
}
