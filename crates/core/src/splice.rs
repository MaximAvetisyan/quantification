use crate::config::MarkerStyle;
use crate::ledger::{Commit, Ledger, marker_len};
use crate::render::render_into;

pub fn spliced_len(input_len: usize, style: MarkerStyle, commits: &[Commit]) -> usize {
    commits.iter().fold(input_len, |len, commit| {
        len.saturating_sub(commit.removed.len())
            + commit.anchor.len()
            + marker_len(style, commit.kind, commit.count)
    })
}

pub fn splice_into<'o>(
    input: &[u8],
    style: MarkerStyle,
    commits: &[Commit],
    out: &'o mut Vec<u8>,
) -> &'o [u8] {
    out.clear();
    out.reserve(spliced_len(input.len(), style, commits));
    let mut at = 0usize;
    for commit in commits {
        assert!(
            at <= commit.removed.start && commit.removed.end <= input.len(),
            "commits must be ascending, disjoint and in bounds"
        );
        let anchor = &input[commit.anchor.clone()];
        out.extend_from_slice(&input[at..commit.removed.start]);
        out.extend_from_slice(anchor);
        render_into(out, style, commit.kind, commit.count, anchor);
        at = commit.removed.end;
    }
    out.extend_from_slice(&input[at..]);
    out
}

pub fn splice_ledger<'o>(input: &[u8], ledger: &Ledger, out: &'o mut Vec<u8>) -> &'o [u8] {
    splice_into(input, ledger.marker_style(), ledger.commits(), out)
}
