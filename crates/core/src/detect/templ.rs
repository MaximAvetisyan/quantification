use std::ops::Range;

use crate::fingerprint::{FingerprintTable, Insert, fingerprint};
use crate::ledger::{CommitKind, CommitOutcome, Ledger, Proposal, StageStats};
use crate::mask::mask_into;
use crate::stage1::Unit;
use crate::wsnorm::normalize_into;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TemplateId(pub u64);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scratch {
    ws: Vec<u8>,
    form: Vec<u8>,
}

impl Scratch {
    pub fn with_capacity(ws: usize, form: usize) -> Self {
        Self {
            ws: Vec::with_capacity(ws),
            form: Vec::with_capacity(form),
        }
    }

    pub fn reserved(&self) -> (usize, usize) {
        (self.ws.capacity(), self.form.capacity())
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
    pub fn build(span: &[u8], units: &[Unit], scratch: &mut Scratch) -> Option<Self> {
        let mut table = FingerprintTable::for_keys(span.len());
        let mut forms = Self {
            bytes: Vec::with_capacity(span.len()),
            units: Vec::with_capacity(units.len()),
        };
        for (index, unit) in units.iter().enumerate() {
            normalize_into(&span[unit.range.clone()], &mut scratch.ws);
            mask_into(&scratch.ws, &mut scratch.form);
            let masked = forms.bytes.len()..forms.bytes.len() + scratch.form.len();
            forms.bytes.extend_from_slice(&scratch.form);
            let hash = fingerprint(&scratch.form);
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
