use std::ops::Range;

use crate::fingerprint::{FingerprintTable, Insert, fingerprint};
use crate::ledger::{CommitKind, CommitOutcome, Ledger, Proposal, StageStats};
use crate::mask::mask_len;
use crate::stage1::Unit;
use crate::wsnorm::Column;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TemplateId(pub u64);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scratch {
    form: Vec<u8>,
}

impl Scratch {
    pub fn with_capacity(form: usize) -> Self {
        Self {
            form: Vec::with_capacity(form * 5 + 8),
        }
    }

    pub fn reserved(&self) -> usize {
        self.form.capacity()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    pub masked: Range<usize>,
    pub id: TemplateId,
    pub hash: u128,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Forms {
    pub bytes: Vec<u8>,
    pub units: Vec<Template>,
}

impl Forms {
    pub fn build(column: &Column, units: &[Unit], scratch: &mut Scratch) -> Option<Self> {
        let mut table = FingerprintTable::for_keys(column.span_bytes);
        let mut forms = Self {
            bytes: Vec::with_capacity(column.bytes.len()),
            units: Vec::with_capacity(units.len()),
        };
        for index in 0..units.len() {
            let len = mask_len(column.get(index), &mut scratch.form);
            let masked = forms.bytes.len()..forms.bytes.len() + len;
            forms.bytes.extend_from_slice(&scratch.form[..len]);
            let hash = fingerprint(&scratch.form[..len]);
            let id = match table.insert_hashed(&forms.bytes, masked.clone(), index, hash) {
                Insert::New => TemplateId(hash as u64),
                Insert::Duplicate(rep) => forms.units[rep].id,
                Insert::Full => return None,
            };
            forms.units.push(Template { masked, id, hash });
        }
        Some(forms)
    }

    pub fn len(&self) -> usize {
        self.units.len()
    }

    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    pub fn masked(&self, unit: usize) -> &[u8] {
        &self.bytes[self.units[unit].masked.clone()]
    }

    pub fn id(&self, unit: usize) -> TemplateId {
        self.units[unit].id
    }

    pub fn same(&self, left: usize, right: usize) -> bool {
        let (first, second) = (self.masked(left), self.masked(right));
        first.len() == second.len()
            && self.units[left].hash == self.units[right].hash
            && first == second
    }

    pub fn block(&self, start: usize, len: usize) -> &[u8] {
        &self.bytes[self.units[start].masked.start..self.units[start + len - 1].masked.end]
    }
}

pub fn template_groups(forms: &Forms, ledger: &mut Ledger<'_>, min_group_size: u32) -> StageStats {
    walk_templates(ledger, forms, min_group_size)
}

fn walk_templates(ledger: &mut Ledger<'_>, forms: &Forms, min_group_size: u32) -> StageStats {
    let units = ledger.units();
    let min = min_group_size.max(2) as usize;
    let mut stats = StageStats::default();
    let mut at = 0;
    while at < units.len() {
        if ledger.is_committed(at) || !units[at].eligible {
            at += 1;
            continue;
        }
        let mut end = at + 1;
        while end < units.len()
            && !ledger.is_committed(end)
            && units[end].eligible
            && forms.same(at, end)
        {
            end += 1;
        }
        if end - at >= min
            && let CommitOutcome::Committed(commit) =
                ledger.try_commit(Proposal::run(at..end, CommitKind::TemplateGroup))
        {
            stats.bump(commit.kind);
        }
        at = end;
    }
    stats
}
