use std::ops::Range;

use crate::fingerprint::{FingerprintTable, Insert, fingerprint};
use crate::ledger::{CommitKind, CommitOutcome, Ledger, Proposal, StageStats};
use crate::wsnorm::normalize_into;

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
    ledger: &mut Ledger<'_>,
    min_block_lines: u32,
    max_block_lines: u32,
    scratch: &mut Scratch,
) -> StageStats {
    if !load(span, ledger, scratch) {
        scratch.degraded = true;
        return StageStats::default();
    }
    let min = min_block_lines.max(1) as usize;
    let max = max_block_lines.max(1) as usize;
    let mut same_bytes = |first: usize, second: usize, len: usize| {
        block(&scratch.norm, &scratch.arena, first, len)
            == block(&scratch.norm, &scratch.arena, second, len)
    };
    windowed_blocks(
        ledger,
        &scratch.ids,
        min,
        max,
        &mut same_bytes,
        &mut scratch.work,
    )
}

fn load(span: &[u8], ledger: &Ledger<'_>, scratch: &mut Scratch) -> bool {
    let units = ledger.units();
    scratch.arena.clear();
    scratch.line.clear();
    scratch.norm.clear();
    scratch.ids.clear();
    scratch.work = Work::default();
    scratch.degraded = false;
    scratch.norm.resize(units.len(), None);
    scratch.ids.resize(units.len(), None);
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
                scratch.norm.clear();
                scratch.norm.resize(units.len(), None);
                scratch.ids.clear();
                scratch.ids.resize(units.len(), None);
                return false;
            }
        };
        scratch.norm[index] = Some(range);
        scratch.ids[index] = Some(rep);
    }
    true
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

pub(crate) fn windowed_blocks(
    ledger: &mut Ledger<'_>,
    ids: &[Option<usize>],
    min_block_lines: usize,
    max_block_lines: usize,
    same_bytes: &mut impl FnMut(usize, usize, usize) -> bool,
    work: &mut Work,
) -> StageStats {
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
                if same_bytes(at, at + length, length) {
                    let copies = copies(ids, at, length, room, same_bytes, work);
                    let group = at..at + copies * length;
                    if let CommitOutcome::Committed(commit) = ledger.try_commit(Proposal::repeat(
                        group.clone(),
                        length,
                        CommitKind::Block,
                    )) {
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
