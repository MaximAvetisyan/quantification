use crate::fingerprint::{FingerprintTable, Insert};
use crate::ledger::{CommitKind, CommitOutcome, Ledger, Proposal, StageStats};
use crate::wsnorm::Column;

use super::templ::Forms;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Work {
    pub compares: u64,
    pub verifications: u64,
    pub scanned: u64,
}

pub type UnitId = Option<u32>;

pub struct Scratch {
    ids: Vec<UnitId>,
    coarse: Vec<UnitId>,
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
            ids: Vec::new(),
            coarse: Vec::new(),
            work: Work::default(),
            degraded: false,
        }
    }

    pub fn with_capacity(units: usize) -> Self {
        Self {
            ids: Vec::with_capacity(units),
            coarse: Vec::with_capacity(units),
            ..Self::new()
        }
    }

    pub fn reserved(&self) -> usize {
        self.ids.capacity()
    }

    pub fn work(&self) -> Work {
        self.work
    }

    pub fn degraded(&self) -> bool {
        self.degraded
    }
}

pub fn repeated_blocks(
    column: &Column,
    forms: Option<&Forms>,
    ledger: &mut Ledger<'_>,
    min_block_lines: u32,
    max_block_lines: u32,
    scratch: &mut Scratch,
) -> StageStats {
    if !load(column, forms, ledger, scratch) {
        scratch.degraded = true;
        return StageStats::default();
    }
    let min = min_block_lines.max(1) as usize;
    let max = max_block_lines.max(1) as usize;
    let mut same_bytes = |first: usize, second: usize, len: usize| {
        column.block(first, len) == column.block(second, len)
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

fn load(
    column: &Column,
    forms: Option<&Forms>,
    ledger: &Ledger<'_>,
    scratch: &mut Scratch,
) -> bool {
    let units = ledger.units();
    reset(scratch, units.len());
    scratch.work = Work::default();
    scratch.degraded = false;
    let mut table = FingerprintTable::for_keys(column.span_bytes);
    for index in 0..units.len() {
        if !units[index].eligible || ledger.is_committed(index) {
            continue;
        }
        let rep = match table.insert_hashed(
            &column.bytes,
            column.range(index),
            index,
            column.hash[index],
        ) {
            Insert::New => index,
            Insert::Duplicate(rep) => rep,
            Insert::Full => {
                reset(scratch, units.len());
                return false;
            }
        };
        scratch.ids[index] = Some(rep as u32);
        scratch.coarse[index] = Some(match forms {
            Some(forms) => forms.id(index).0 as u32,
            None => rep as u32,
        });
    }
    true
}

fn reset(scratch: &mut Scratch, units: usize) {
    for column in [&mut scratch.ids, &mut scratch.coarse] {
        column.clear();
        column.resize(units, None);
    }
}

pub(crate) struct Domain<'a, S, W, C> {
    pub ids: &'a [UnitId],
    pub same_bytes: S,
    pub left_wall: W,
    pub coarse_ids: &'a [UnitId],
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
    let mut compares = work.compares;
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
        let head = ids[at];
        while length >= min {
            compares += 1;
            if head == ids[at + length] && equal_tail(ids, at, at + length, length, &mut compares) {
                work.verifications += 1;
                if (domain.same_bytes)(at, at + length, length)
                    && anchor_is_match_free(domain, at, length, &mut compares, work)
                {
                    if wall_blocks(ledger, domain, at) {
                        break;
                    }
                    let copies = copies(
                        ids,
                        at,
                        length,
                        room,
                        &mut domain.same_bytes,
                        &mut compares,
                        work,
                    );
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
    work.compares = compares;
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
    compares: &mut u64,
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
            *compares += 1;
            if ids[start] == ids[start + period]
                && equal_tail(ids, start, start + period, period, compares)
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

fn equal_tail(ids: &[UnitId], first: usize, second: usize, len: usize, compares: &mut u64) -> bool {
    for at in 1..len {
        *compares += 1;
        if ids[first + at] != ids[second + at] {
            return false;
        }
    }
    true
}

fn copies(
    ids: &[UnitId],
    at: usize,
    length: usize,
    room: usize,
    same_bytes: &mut impl FnMut(usize, usize, usize) -> bool,
    compares: &mut u64,
    work: &mut Work,
) -> usize {
    let mut copies = 2;
    while (copies + 1) * length <= room {
        let first = at + (copies - 1) * length;
        let second = first + length;
        *compares += 1;
        if ids[first] != ids[second] || !equal_tail(ids, first, second, length, compares) {
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
