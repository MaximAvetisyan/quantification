use crate::fingerprint::fingerprint;
use crate::ledger::{CommitKind, Ledger, StageStats};
use crate::stage1::Unit;
use crate::wsnorm::normalize_into;

use super::exact::walk_runs;

#[derive(Clone, Debug, Default)]
pub struct Scratch {
    head: Vec<u8>,
    next: Vec<u8>,
}

impl Scratch {
    pub fn with_capacity(head: usize, next: usize) -> Self {
        Self {
            head: Vec::with_capacity(head),
            next: Vec::with_capacity(next),
        }
    }

    pub fn reserved(&self) -> (usize, usize) {
        (self.head.capacity(), self.next.capacity())
    }
}

pub fn ws_runs(
    span: &[u8],
    ledger: &mut Ledger<'_>,
    min_group_size: u32,
    scratch: &mut Scratch,
) -> StageStats {
    let mut same = |left: &Unit, right: &Unit| {
        normalize_into(&span[left.range.clone()], &mut scratch.head);
        normalize_into(&span[right.range.clone()], &mut scratch.next);
        let (head, next) = (&scratch.head, &scratch.next);
        head.len() == next.len() && fingerprint(head) == fingerprint(next) && head == next
    };
    walk_runs(ledger, min_group_size, CommitKind::WsRun, &mut same)
}
