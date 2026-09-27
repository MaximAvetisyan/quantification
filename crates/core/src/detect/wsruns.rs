use crate::fingerprint::fingerprint;
use crate::ledger::{CommitKind, Ledger, StageStats};
use crate::stage1::Unit;
use crate::wsnorm::normalize_into;

use super::exact::walk_runs;

#[derive(Clone, Debug, Default)]
pub struct Scratch {
    head: Vec<u8>,
    next: Vec<u8>,
    head_hash: u128,
    next_hash: u128,
    next_at: usize,
    primed: bool,
}

impl Scratch {
    pub fn with_capacity(head: usize, next: usize) -> Self {
        Self {
            head: Vec::with_capacity(head),
            next: Vec::with_capacity(next),
            ..Self::default()
        }
    }

    pub fn reserved(&self) -> (usize, usize) {
        (self.head.capacity(), self.next.capacity())
    }

    fn take_head(&mut self, span: &[u8], left: &Unit) {
        if self.primed && self.next_at == left.range.start {
            std::mem::swap(&mut self.head, &mut self.next);
            std::mem::swap(&mut self.head_hash, &mut self.next_hash);
            self.primed = false;
            return;
        }
        normalize_into(&span[left.range.clone()], &mut self.head);
        self.head_hash = fingerprint(&self.head);
    }

    fn take_next(&mut self, span: &[u8], right: &Unit) {
        normalize_into(&span[right.range.clone()], &mut self.next);
        self.next_hash = fingerprint(&self.next);
        self.next_at = right.range.start;
        self.primed = true;
    }

    fn same(&self) -> bool {
        self.head.len() == self.next.len()
            && self.head_hash == self.next_hash
            && self.head == self.next
    }
}

pub fn ws_runs(
    span: &[u8],
    ledger: &mut Ledger<'_>,
    min_group_size: u32,
    scratch: &mut Scratch,
) -> StageStats {
    let mut same = |left: &Unit, right: &Unit| {
        scratch.take_head(span, left);
        scratch.take_next(span, right);
        scratch.same()
    };
    walk_runs(ledger, min_group_size, CommitKind::WsRun, &mut same)
}
