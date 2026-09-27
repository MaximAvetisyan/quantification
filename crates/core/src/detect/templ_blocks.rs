use crate::detect::blocks::{Domain, NONE, Work, windowed_blocks};
use crate::ledger::{CommitKind, Ledger, StageStats};

use super::templ::Forms;

const MIN_PERIOD: usize = 1;

pub struct Scratch {
    ids: Vec<u32>,
    work: Work,
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
            work: Work::default(),
        }
    }

    pub fn with_capacity(units: usize) -> Self {
        Self {
            ids: Vec::with_capacity(units),
            work: Work::default(),
        }
    }

    pub fn reserved(&self) -> usize {
        self.ids.capacity()
    }

    pub fn work(&self) -> Work {
        self.work
    }
}

pub fn templated_blocks(
    forms: Option<&Forms>,
    ledger: &mut Ledger<'_>,
    max_block_lines: u32,
    scratch: &mut Scratch,
) -> StageStats {
    let Some(forms) = forms else {
        return StageStats::default();
    };
    load(ledger, forms, scratch);
    let mut same = |first: usize, second: usize, length: usize| {
        forms.block(first, length) == forms.block(second, length)
    };
    let mut coarse = |first: usize, second: usize| forms.same(first, second);
    let mut left_wall = |before: usize, first: usize| forms.same(before, first);
    let mut domain = Domain {
        ids: &scratch.ids,
        same_bytes: &mut same,
        left_wall: &mut left_wall,
        coarse_ids: &scratch.ids,
        coarse_same: &mut coarse,
    };
    windowed_blocks(
        ledger,
        &mut domain,
        MIN_PERIOD,
        max_block_lines.max(1) as usize,
        CommitKind::TemplatedBlock,
        &mut scratch.work,
    )
}

fn load(ledger: &Ledger<'_>, forms: &Forms, scratch: &mut Scratch) {
    let units = ledger.units();
    scratch.ids.clear();
    scratch.ids.resize(units.len(), NONE);
    scratch.work = Work::default();
    for (index, unit) in units.iter().enumerate().take(forms.len()) {
        if unit.eligible {
            scratch.ids[index] = forms.id(index).0 as u32;
        }
    }
}
