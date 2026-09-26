use crate::detect::blocks::{Work, windowed_blocks};
use crate::ledger::{CommitKind, Ledger, StageStats};

use super::templ::{Forms, Templated};

const MIN_PERIOD: usize = 1;

pub struct Scratch {
    ids: Vec<Option<usize>>,
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
    templated: &Templated,
    ledger: &mut Ledger<'_>,
    max_block_lines: u32,
    scratch: &mut Scratch,
) -> StageStats {
    if templated.degraded {
        return StageStats::default();
    }
    let forms = &templated.forms;
    load(ledger, forms, scratch);
    let mut same = |first: usize, second: usize, length: usize| {
        masked(forms, first, length) == masked(forms, second, length)
    };
    windowed_blocks(
        ledger,
        &scratch.ids,
        MIN_PERIOD,
        max_block_lines.max(1) as usize,
        CommitKind::TemplatedBlock,
        &mut same,
        &mut scratch.work,
    )
}

fn load(ledger: &Ledger<'_>, forms: &Forms, scratch: &mut Scratch) {
    let units = ledger.units();
    scratch.ids.clear();
    scratch.ids.resize(units.len(), None);
    scratch.work = Work::default();
    for (index, unit) in units.iter().enumerate().take(forms.len()) {
        if unit.eligible {
            scratch.ids[index] = Some(forms.id(index).0 as usize);
        }
    }
}

fn masked(forms: &Forms, start: usize, length: usize) -> &[u8] {
    &forms.bytes[forms.units[start].masked.start..forms.units[start + length - 1].masked.end]
}
