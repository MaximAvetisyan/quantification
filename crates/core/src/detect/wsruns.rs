use crate::ledger::{CommitKind, Ledger, StageStats};
use crate::wsnorm::Column;

use super::exact::walk_runs;

pub fn ws_runs(column: &Column, ledger: &mut Ledger<'_>, min_group_size: u32) -> StageStats {
    let mut same = |left: usize, right: usize| {
        column.len[left] == column.len[right]
            && column.hash[left] == column.hash[right]
            && column.get(left) == column.get(right)
    };
    walk_runs(ledger, min_group_size, CommitKind::WsRun, &mut same)
}
