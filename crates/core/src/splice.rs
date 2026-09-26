use crate::ledger::{Commit, Ledger, marker_len};
use crate::render::render_into;

pub fn spliced_len(input_len: usize, commits: &[Commit]) -> usize {
    commits.iter().fold(input_len, |len, commit| {
        len.saturating_sub(commit.removed.len())
            + commit.anchor.len()
            + marker_len(commit.style, commit.kind, commit.count)
    })
}

pub fn splice_into<'o>(input: &[u8], commits: &[Commit], out: &'o mut Vec<u8>) -> &'o [u8] {
    out.clear();
    out.reserve(spliced_len(input.len(), commits));
    let mut at = 0usize;
    for commit in commits {
        assert!(
            at <= commit.removed.start && commit.removed.end <= input.len(),
            "commits must be ascending, disjoint and in bounds"
        );
        assert!(
            commit.removed.start <= commit.anchor.start && commit.anchor.end <= commit.removed.end,
            "the anchor is a sub-range of the range it replaces"
        );
        let anchor = &input[commit.anchor.clone()];
        out.extend_from_slice(&input[at..commit.removed.start]);
        out.extend_from_slice(anchor);
        render_into(out, commit.style, commit.kind, commit.count, anchor);
        at = commit.removed.end;
    }
    out.extend_from_slice(&input[at..]);
    out
}

pub fn splice_ledger<'o>(input: &[u8], ledger: &Ledger, out: &'o mut Vec<u8>) -> &'o [u8] {
    splice_into(input, ledger.commits(), out)
}
