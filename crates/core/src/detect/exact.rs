use crate::fingerprint::fingerprint;
use crate::ledger::{CommitKind, CommitOutcome, Ledger, Proposal, StageStats};
use crate::stage1::Unit;

pub fn exact_runs(span: &[u8], ledger: &mut Ledger<'_>, min_group_size: u32) -> StageStats {
    let mut same = |left: &Unit, right: &Unit| raw_equal(span, left, right);
    walk_runs(ledger, min_group_size, CommitKind::ExactRun, &mut same)
}

fn raw_equal(span: &[u8], left: &Unit, right: &Unit) -> bool {
    let (first, second) = (&span[left.range.clone()], &span[right.range.clone()]);
    first.len() == second.len() && fingerprint(first) == fingerprint(second) && first == second
}

pub(crate) fn walk_runs(
    ledger: &mut Ledger<'_>,
    min_group_size: u32,
    kind: CommitKind,
    same: &mut impl FnMut(&Unit, &Unit) -> bool,
) -> StageStats {
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
            && same(&units[at], &units[end])
        {
            end += 1;
        }
        if end - at >= min
            && let CommitOutcome::Committed(commit) =
                ledger.try_commit(Proposal::run(at..end, kind))
        {
            stats.bump(commit.kind);
        }
        at = end;
    }
    stats
}
