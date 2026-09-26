use std::ops::Range;

use quantification_core::config::{MAX_LINE_BYTES, MAX_RECORD_BYTES, MarkerStyle};
use quantification_core::fingerprint::marker_checksum;
use quantification_core::ledger::{
    Commit, CommitKind, CommitOutcome, Ledger, Proposal, StageStats, decimal_width, framing,
    marker_len, profitable, removal_range,
};
use quantification_core::stage1::{Unit, joiner, split_span};

const UNICODE: MarkerStyle = MarkerStyle::Unicode;
const ASCII: MarkerStyle = MarkerStyle::Ascii;

fn line_span(count: usize, len: usize) -> Vec<u8> {
    let mut span = Vec::new();
    for i in 0..count {
        if i > 0 {
            span.extend_from_slice(br"\n");
        }
        span.extend(std::iter::repeat_n(b'x', len));
    }
    span
}

fn record(len: usize) -> Vec<u8> {
    let mut bytes = vec![b'{'];
    bytes.extend(std::iter::repeat_n(b'a', len - 2));
    bytes.push(b'}');
    bytes
}

fn dump(records: &[usize]) -> Vec<u8> {
    let mut span = vec![b'['];
    for (i, len) in records.iter().enumerate() {
        if i > 0 {
            span.push(b',');
        }
        span.extend_from_slice(&record(*len));
    }
    span.push(b']');
    span
}

fn ledger<'a>(units: &'a [Unit]) -> Ledger<'a> {
    Ledger::new(units, UNICODE)
}

fn committed(outcome: CommitOutcome) -> Commit {
    match outcome {
        CommitOutcome::Committed(commit) => commit,
        other => panic!("expected a commit, got {other:?}"),
    }
}

fn render(style: MarkerStyle, kind: CommitKind, count: u64, anchor: &[u8]) -> String {
    let (open, sep, close) = framing(style);
    let (prefix, suffix) = kind.core(style);
    let marker = format!(
        "{open}{prefix}{count}{suffix}{sep}{:04x}{close}",
        marker_checksum(anchor)
    );
    assert_eq!(marker.len(), marker_len(style, kind, count));
    marker
}

fn commit_of(units: &[Unit], proposal: Proposal) -> Commit {
    committed(ledger(units).try_commit(proposal))
}

fn assert_removal_invariant(units: &[Unit], group: &Range<usize>, removed: &Range<usize>) {
    let members = &units[group.clone()];
    let gaps: usize = members
        .windows(2)
        .map(|pair| pair[1].range.start - pair[0].range.end)
        .sum();
    let members_bytes: usize = members.iter().map(|unit| unit.range.len()).sum();
    assert_eq!(
        *removed,
        members[0].range.start..members[members.len() - 1].range.end
    );
    assert_eq!(removed.len(), members_bytes + gaps);
}

#[test]
fn removal_range_is_the_member_union_plus_inter_member_joiners() {
    let span = line_span(6, 9);
    let units = split_span(&span);
    assert_eq!(units.len(), 6);
    for group in [0..1, 0..6, 1..4, 2..5, 5..6, 3..4] {
        let removed = removal_range(&units, group.clone());
        assert_removal_invariant(&units, &group, &removed);
        assert_eq!(
            removed,
            units[group.start].range.start..units[group.end - 1].range.end
        );
        assert_eq!(removed.len(), 9 * group.len() + 2 * (group.len() - 1));
    }
}

#[test]
fn removal_range_keeps_the_joiner_of_every_surviving_neighbour() {
    let span = line_span(4, 30);
    let units = split_span(&span);
    let first = committed(ledger(&units).try_commit(Proposal::run(0..2, CommitKind::ExactRun)));
    let last = committed(ledger(&units).try_commit(Proposal::run(2..4, CommitKind::ExactRun)));
    assert_eq!(first.removed.start, 0);
    assert_eq!(last.removed.end, span.len());
    assert_eq!(first.anchor, 0..30);
    assert_eq!(last.anchor, units[2].range.clone());
    assert_eq!(&span[first.removed.clone()], &line_span(2, 30)[..]);
    assert_eq!(&span[last.removed.clone()], &line_span(2, 30)[..]);
    assert_eq!(&span[units[1].range.end..units[2].range.start], br"\n");
    assert!(last.removed.start > units[1].range.end);
    assert!(first.removed.end < units[2].range.start);
}

#[test]
fn removal_range_spans_mixed_line_boundary_joiner_forms() {
    let span = br"a\nbb\u000Acc\u000Add".to_vec();
    let units = split_span(&span);
    assert_eq!(units.len(), 4);
    assert_eq!(&span[units[0].range.clone()], b"a");
    assert_eq!(&span[units[1].range.clone()], b"bb");
    assert_eq!(&span[units[2].range.clone()], b"cc");
    assert_eq!(&span[units[3].range.clone()], b"dd");
    assert_eq!(joiner(&units, 0, span.len()).len(), 2);
    assert_eq!(joiner(&units, 1, span.len()).len(), 6);
    assert_eq!(joiner(&units, 2, span.len()).len(), 6);
    assert_eq!(joiner(&units, 3, span.len()).len(), 0);
    let removed = removal_range(&units, 0..3);
    assert_removal_invariant(&units, &(0..3), &removed);
    assert_eq!(&span[removed.clone()], br"a\nbb\u000Acc");
    assert_eq!(removed.len(), 1 + 2 + 2 + 6 + 2);
    let middle = removal_range(&units, 1..2);
    assert_eq!(&span[middle.clone()], b"bb");
    assert_eq!(middle.len(), 2);
    let tail = removal_range(&units, 3..4);
    assert_eq!(&span[tail], b"dd");
}

#[test]
fn removal_range_spans_concatenated_boundary_joiners() {
    let span = br"a\n\u000Ab\n\u000Ac".to_vec();
    let units = split_span(&span);
    assert_eq!(units.len(), 3);
    assert_eq!(joiner(&units, 0, span.len()).len(), 8);
    assert_eq!(joiner(&units, 1, span.len()).len(), 8);
    assert_eq!(joiner(&units, 2, span.len()).len(), 0);
    let removed = removal_range(&units, 0..3);
    assert_removal_invariant(&units, &(0..3), &removed);
    assert_eq!(&span[removed.clone()], br"a\n\u000Ab\n\u000Ac");
    assert_eq!(removed.len(), 1 + 8 + 1 + 8 + 1);
}

#[test]
fn removal_range_over_stage1b_comma_separators() {
    let span = dump(&vec![200; 400]);
    assert!(span.len() > MAX_LINE_BYTES);
    let units = split_span(&span);
    assert_eq!(units.len(), 400);
    assert_eq!(units[0].range.len(), 201);
    assert_eq!(units[399].range.len(), 201);
    assert!(span[units[0].range.clone()].starts_with(b"[{"));
    assert!(span[units[399].range.clone()].ends_with(b"}]"));
    for index in 1..399 {
        assert_eq!(units[index].range.len(), 200);
        assert_eq!(&span[joiner(&units, index, span.len())], b",");
    }
    let removed = removal_range(&units, 2..5);
    assert_removal_invariant(&units, &(2..5), &removed);
    let mut expected = Vec::new();
    for (index, unit) in units[2..5].iter().enumerate() {
        if index > 0 {
            expected.push(b',');
        }
        expected.extend_from_slice(&span[unit.range.clone()]);
    }
    assert_eq!(&span[removed.clone()], &expected[..]);
    assert_eq!(removed.len(), 3 * 200 + 2);
    assert_eq!(removal_range(&units, 0..1), 0..201);
}

#[test]
fn removal_range_handles_line_and_record_joiners_in_one_span() {
    let mut span = line_span(3, 30);
    span.extend_from_slice(br"\n");
    span.extend_from_slice(&dump(&vec![200; 400]));
    let units = split_span(&span);
    assert_eq!(units.len(), 3 + 400);
    assert_eq!(&span[joiner(&units, 0, span.len())], br"\n");
    assert_eq!(&span[joiner(&units, 2, span.len())], br"\n");
    assert_eq!(&span[joiner(&units, 5, span.len())], b",");
    assert_eq!(&span[joiner(&units, 401, span.len())], b",");
    assert_eq!(joiner(&units, 402, span.len()).len(), 0);
    let mut ledger = ledger(&units);
    let lines = committed(ledger.try_commit(Proposal::run(0..3, CommitKind::WsRun)));
    let records = committed(ledger.try_commit(Proposal::run(5..8, CommitKind::Block)));
    let head = committed(ledger.try_commit(Proposal::repeat(3..5, 1, CommitKind::Block)));
    assert_eq!(lines.removed, 0..units[2].range.end);
    assert_eq!(lines.removed.len(), 3 * 30 + 2 * 2);
    assert_eq!(records.removed.len(), 3 * 200 + 2);
    assert_eq!(head.removed.len(), 201 + 200 + 1);
    assert_eq!(
        ledger
            .commits()
            .iter()
            .map(|commit| (commit.anchor.start, commit.removed.len()))
            .collect::<Vec<_>>(),
        [
            (0, 94),
            (units[3].range.start, 402),
            (units[5].range.start, 602)
        ]
    );
    for commit in ledger.commits() {
        assert_removal_invariant(
            &units,
            &(commit.first..commit.last + 1),
            &commit.removed.clone(),
        );
    }
}

#[test]
fn removal_range_over_a_single_member_group() {
    let units = split_span(&line_span(3, 5));
    for index in 0..3 {
        let group = index..index + 1;
        let removed = removal_range(&units, group.clone());
        assert_eq!(removed, units[index].range.clone());
        assert_eq!(removed.len(), 5);
        assert_removal_invariant(&units, &group, &removed);
    }
}

#[test]
fn ledger_never_inflates_removed_bytes_after_earlier_commits() {
    let span = line_span(12, 30);
    let units = split_span(&span);
    let mut ledger = ledger(&units);
    committed(ledger.try_commit(Proposal::run(6..9, CommitKind::ExactRun)));
    let residual: Vec<Unit> = ledger.residual().map(|(_, unit)| unit.clone()).collect();
    assert_eq!(residual.len(), 9);
    assert_eq!(joiner(&residual, 5, span.len()).start, units[5].range.end);
    assert_eq!(joiner(&residual, 5, span.len()).len(), 98);
    assert_eq!(
        ledger.try_commit(Proposal::run(5..9, CommitKind::WsRun)),
        CommitOutcome::Overlapped
    );
    let middle = committed(ledger.try_commit(Proposal::run(3..6, CommitKind::ExactRun)));
    assert_eq!(middle.removed, units[3].range.start..units[5].range.end);
    assert_eq!(middle.removed.len(), 3 * 30 + 2 * 2);
    assert!(middle.removed.end <= units[6].range.start);
    let first = committed(ledger.try_commit(Proposal::run(0..3, CommitKind::ExactRun)));
    assert_eq!(first.removed, 0..units[2].range.end);
    let mut at = 0;
    let mut removed_total = 0;
    for commit in ledger.commits() {
        assert_removal_invariant(
            &units,
            &(commit.first..commit.last + 1),
            &commit.removed.clone(),
        );
        assert!(commit.removed.start >= at);
        at = commit.removed.end;
        removed_total += commit.removed.len();
    }
    let mut surviving = 0;
    for (index, unit) in units.iter().enumerate() {
        if ledger.is_committed(index) {
            continue;
        }
        assert!(
            unit.range.start >= at,
            "a survivor sits inside a removed range"
        );
        at = unit.range.end;
        surviving += unit.range.len();
    }
    assert_eq!(at, span.len());
    assert_eq!((span.len() - removed_total - surviving) / 2, 11 - 2 * 3);
}

#[test]
fn gate_rejects_exact_equality() {
    let count = Proposal::run(0..3, CommitKind::ExactRun).count;
    assert_eq!(count, 2);
    let marker = marker_len(UNICODE, CommitKind::ExactRun, count);
    let span = line_span(3, 11);
    let units = split_span(&span);
    assert_eq!(span.len(), 3 * 11 + 2 * 2);
    assert_eq!(11 + marker, span.len());
    let mut ledger = ledger(&units);
    assert_eq!(
        ledger.try_commit(Proposal::run(0..3, CommitKind::ExactRun)),
        CommitOutcome::BelowThreshold
    );
    assert!(!profitable(
        UNICODE,
        CommitKind::ExactRun,
        count,
        11,
        span.len()
    ));
    assert!(profitable(
        UNICODE,
        CommitKind::ExactRun,
        count,
        11,
        span.len() + 1
    ));
    assert_eq!(ledger.commits().len(), 0);
    assert_eq!(ledger.residual().count(), 3);
}

#[test]
fn gate_commits_one_byte_below_equality_and_keeps_verbatim_above() {
    let count = Proposal::run(0..3, CommitKind::ExactRun).count;
    let marker = marker_len(UNICODE, CommitKind::ExactRun, count);
    assert_eq!(marker, 26);
    let wide = split_span(&line_span(3, 12));
    let mut wide_ledger = ledger(&wide);
    assert_eq!(
        committed(wide_ledger.try_commit(Proposal::run(0..3, CommitKind::ExactRun)))
            .removed
            .len(),
        3 * 12 + 4
    );
    let narrow = split_span(&line_span(3, 10));
    let mut ledger = ledger(&narrow);
    assert_eq!(
        ledger.try_commit(Proposal::run(0..3, CommitKind::ExactRun)),
        CommitOutcome::BelowThreshold
    );
    assert!(marker + 12 < 3 * 12 + 4);
    assert!(marker + 11 > 3 * 10 + 4);
}

#[test]
fn gate_boundary_holds_for_the_ascii_style_too() {
    let count = Proposal::run(0..3, CommitKind::WsRun).count;
    let marker = marker_len(ASCII, CommitKind::WsRun, count);
    assert_eq!(marker, 32);
    let exact = split_span(&line_span(3, 14));
    assert_eq!(14 + marker, 3 * 14 + 4);
    let mut ledger = Ledger::new(&exact, ASCII);
    assert_eq!(
        ledger.try_commit(Proposal::run(0..3, CommitKind::WsRun)),
        CommitOutcome::BelowThreshold
    );
    let wider = split_span(&line_span(3, 15));
    let mut ledger = Ledger::new(&wider, ASCII);
    assert_eq!(
        committed(ledger.try_commit(Proposal::run(0..3, CommitKind::WsRun)))
            .removed
            .len(),
        3 * 15 + 4
    );
}

#[test]
fn gate_is_a_pure_function_of_its_inputs() {
    for kind in [
        CommitKind::ExactRun,
        CommitKind::WsRun,
        CommitKind::Block,
        CommitKind::TemplateGroup,
        CommitKind::TemplatedBlock,
    ] {
        for count in [1u64, 2, 9, 10, 99, 100, 1000] {
            let cost = 40 + marker_len(UNICODE, kind, count);
            assert!(!profitable(UNICODE, kind, count, 40, cost));
            assert!(profitable(UNICODE, kind, count, 40, cost + 1));
            assert!(!profitable(UNICODE, kind, count, 40, cost - 1));
            assert_eq!(
                profitable(UNICODE, kind, count, 40, cost + 1),
                profitable(UNICODE, kind, count, 40, cost + 1)
            );
        }
    }
}

#[test]
fn below_threshold_groups_stay_verbatim_and_reusable() {
    let units = split_span(&line_span(3, 4));
    let mut ledger = ledger(&units);
    assert_eq!(
        ledger.try_commit(Proposal::run(0..3, CommitKind::ExactRun)),
        CommitOutcome::BelowThreshold
    );
    assert!(ledger.is_free(0..3));
    assert!(!ledger.is_committed(0));
    assert!(!ledger.is_committed(1));
    assert!(!ledger.is_committed(2));
    assert_eq!(ledger.commits().len(), 0);
    assert_eq!(
        ledger
            .residual()
            .map(|(index, _)| index)
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
}

#[test]
fn decimal_width_accounts_for_every_carry() {
    for (count, width) in [
        (0u64, 1usize),
        (1, 1),
        (9, 1),
        (10, 2),
        (99, 2),
        (100, 3),
        (999, 3),
        (1000, 4),
        (9999, 4),
        (10000, 5),
        (1_000_000, 7),
        (u64::MAX, 20),
    ] {
        assert_eq!(decimal_width(count), width, "count {count}");
        assert_eq!(count.to_string().len(), width, "count {count}");
    }
    for kind in [
        CommitKind::ExactRun,
        CommitKind::WsRun,
        CommitKind::Block,
        CommitKind::TemplateGroup,
        CommitKind::TemplatedBlock,
    ] {
        for style in [UNICODE, ASCII] {
            for (count, width) in [(9u64, 1usize), (10, 2), (99, 2), (100, 3), (1000, 4)] {
                let base = marker_len(style, kind, 1);
                assert_eq!(
                    marker_len(style, kind, count),
                    base + width - 1,
                    "{kind:?} {count}"
                );
            }
            assert_eq!(
                marker_len(style, kind, 10) - marker_len(style, kind, 9),
                1,
                "{kind:?}"
            );
            assert_eq!(
                marker_len(style, kind, 100) - marker_len(style, kind, 99),
                1,
                "{kind:?}"
            );
            assert_eq!(
                marker_len(style, kind, 1000) - marker_len(style, kind, 999),
                1,
                "{kind:?}"
            );
        }
    }
}

#[test]
fn marker_len_is_pinned_for_every_kind_and_style() {
    let table: [(MarkerStyle, CommitKind, u64, usize); 10] = [
        (UNICODE, CommitKind::ExactRun, 1, 26),
        (UNICODE, CommitKind::WsRun, 1, 31),
        (UNICODE, CommitKind::Block, 1, 22),
        (UNICODE, CommitKind::TemplateGroup, 1, 31),
        (UNICODE, CommitKind::TemplatedBlock, 1, 32),
        (ASCII, CommitKind::ExactRun, 1, 27),
        (ASCII, CommitKind::WsRun, 1, 32),
        (ASCII, CommitKind::Block, 1, 23),
        (ASCII, CommitKind::TemplateGroup, 1, 32),
        (ASCII, CommitKind::TemplatedBlock, 1, 33),
    ];
    for (style, kind, count, expect) in table {
        assert_eq!(marker_len(style, kind, count), expect, "{style:?} {kind:?}");
    }
    assert_eq!(CommitKind::ExactRun.core(UNICODE), ("\u{d7}", " identical"));
    assert_eq!(CommitKind::WsRun.core(ASCII), ("x", " rows, ws-equal"));
    assert_eq!(CommitKind::Block.core(UNICODE), ("block \u{d7}", ""));
    assert_eq!(
        CommitKind::TemplateGroup.core(ASCII),
        ("x", " rows, template")
    );
    assert_eq!(
        CommitKind::TemplatedBlock.core(UNICODE),
        ("templated block \u{d7}", "")
    );
}

#[test]
fn emitted_order_follows_anchor_offsets_not_discovery_order() {
    let units = split_span(&line_span(6, 40));
    let mut ledger = ledger(&units);
    let last = committed(ledger.try_commit(Proposal::new(4..6, 1, 1, CommitKind::Block)));
    let first = committed(ledger.try_commit(Proposal::new(0..2, 1, 1, CommitKind::ExactRun)));
    let middle = committed(ledger.try_commit(Proposal::new(2..4, 1, 1, CommitKind::WsRun)));
    assert_eq!(
        ledger.commits(),
        [first.clone(), middle.clone(), last.clone()]
    );
    assert_eq!(
        ledger
            .commits()
            .iter()
            .map(|commit| commit.anchor.start)
            .collect::<Vec<_>>(),
        [first.anchor.start, middle.anchor.start, last.anchor.start]
    );
    assert!(
        ledger
            .commits()
            .windows(2)
            .all(|pair| pair[0].anchor.start < pair[1].anchor.start)
    );
}

#[test]
fn emitted_order_is_stable_across_repeated_detector_orders() {
    let units = split_span(&line_span(4, 40));
    let orders: [Vec<Range<usize>>; 3] =
        [vec![0..2, 2..4], vec![2..4, 0..2], vec![2..4, 0..1, 0..2]];
    let mut rendered = Vec::new();
    for order in orders {
        let mut ledger = ledger(&units);
        for group in order {
            let _ = ledger.try_commit(Proposal::run(group, CommitKind::TemplateGroup));
        }
        rendered.push(
            ledger
                .commits()
                .iter()
                .map(|commit| (commit.anchor.clone(), commit.removed.clone()))
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(rendered[0], rendered[1]);
    assert_eq!(rendered[0], rendered[2]);
    assert_eq!(rendered[0].len(), 2);
}

#[test]
fn block_anchors_cover_the_whole_first_occurrence() {
    let units = split_span(&line_span(6, 30));
    let mut ledger = ledger(&units);
    let commit = committed(ledger.try_commit(Proposal::repeat(0..6, 2, CommitKind::Block)));
    assert_eq!(commit.anchor, removal_range(&units, 0..2));
    assert_eq!(commit.removed, removal_range(&units, 0..6));
    assert_eq!(commit.members(), 6);
    assert_eq!(commit.count, 2);
    assert!(commit.anchor.start >= commit.removed.start && commit.anchor.end <= commit.removed.end);
    assert!(profitable(
        UNICODE,
        CommitKind::Block,
        2,
        2 * 30 + 2,
        commit.removed.len()
    ));
}

#[test]
fn run_proposals_derive_the_omitted_count_from_the_group() {
    let units = split_span(&line_span(5, 20));
    let proposal = Proposal::run(1..4, CommitKind::WsRun);
    assert_eq!(proposal.anchor_units, 1);
    assert_eq!(proposal.count, 2);
    let mut ledger = ledger(&units);
    let commit = committed(ledger.try_commit(proposal));
    assert_eq!(commit.count, 2);
    assert_eq!(commit.members(), 3);
    assert_eq!(commit.kind, CommitKind::WsRun);
    assert_eq!(commit.first, 1);
    assert_eq!(commit.last, 3);
    assert_eq!(Proposal::run(0..1, CommitKind::ExactRun).count, 0);
    assert_eq!(
        ledger.try_commit(Proposal::run(4..5, CommitKind::ExactRun)),
        CommitOutcome::InvalidCount
    );
}

#[test]
fn a_two_member_run_renders_one_omitted_copy() {
    let span = line_span(2, 30);
    let units = split_span(&span);
    let anchor = &span[units[0].range.clone()];
    let commit = commit_of(&units, Proposal::run(0..2, CommitKind::ExactRun));
    assert_eq!(commit.count, 1);
    assert_eq!(commit.members(), 2);
    assert_eq!(decimal_width(commit.count), 1);
    assert_eq!(
        render(UNICODE, CommitKind::ExactRun, commit.count, anchor),
        "\u{27ea}\u{d7}1 identical \u{b7}4141\u{27eb}"
    );
    assert_eq!(
        render(ASCII, CommitKind::ExactRun, commit.count, anchor),
        "[... x1 identical 4141 ...]"
    );
}

#[test]
fn a_ten_member_run_renders_nine_omitted_copies() {
    let span = line_span(10, 20);
    let units = split_span(&span);
    let anchor = &span[units[0].range.clone()];
    let commit = commit_of(&units, Proposal::run(0..10, CommitKind::ExactRun));
    assert_eq!(commit.count, 9);
    assert_eq!(commit.members(), 10);
    assert_eq!(decimal_width(commit.count), 1);
    assert_eq!(
        render(UNICODE, CommitKind::ExactRun, commit.count, anchor),
        "\u{27ea}\u{d7}9 identical \u{b7}72bf\u{27eb}"
    );
    assert_eq!(
        render(ASCII, CommitKind::ExactRun, commit.count, anchor),
        "[... x9 identical 72bf ...]"
    );
}

#[test]
fn an_eleven_member_run_renders_ten_omitted_copies_across_the_width_carry() {
    let span = line_span(11, 20);
    let units = split_span(&span);
    let anchor = &span[units[0].range.clone()];
    let commit = commit_of(&units, Proposal::run(0..11, CommitKind::ExactRun));
    assert_eq!(commit.count, 10);
    assert_eq!(commit.members(), 11);
    assert_eq!(decimal_width(commit.count), 2);
    assert_eq!(
        render(UNICODE, CommitKind::ExactRun, commit.count, anchor),
        "\u{27ea}\u{d7}10 identical \u{b7}72bf\u{27eb}"
    );
    assert_eq!(
        render(ASCII, CommitKind::ExactRun, commit.count, anchor),
        "[... x10 identical 72bf ...]"
    );
}

#[test]
fn a_two_hundred_copy_run_renders_one_hundred_ninety_nine() {
    let span = line_span(200, 20);
    let units = split_span(&span);
    let anchor = &span[units[0].range.clone()];
    let commit = commit_of(&units, Proposal::run(0..200, CommitKind::ExactRun));
    assert_eq!(commit.count, 199);
    assert_eq!(commit.members(), 200);
    assert_eq!(commit.anchor.len(), 20);
    assert_eq!(commit.removed.len(), 200 * 20 + 2 * 199);
    assert_eq!(
        render(UNICODE, CommitKind::ExactRun, commit.count, anchor),
        "\u{27ea}\u{d7}199 identical \u{b7}72bf\u{27eb}"
    );
    assert_eq!(
        render(ASCII, CommitKind::ExactRun, commit.count, anchor),
        "[... x199 identical 72bf ...]"
    );
}

#[test]
fn a_block_group_of_two_three_unit_copies_renders_one_omitted_copy() {
    let span = line_span(6, 20);
    let units = split_span(&span);
    let anchor = &span[removal_range(&units, 0..3)];
    let commit = commit_of(&units, Proposal::repeat(0..6, 3, CommitKind::Block));
    assert_eq!(commit.count, 1);
    assert_eq!(commit.members(), 6);
    assert_eq!(commit.anchor.len(), 3 * 20 + 2 * 2);
    assert_eq!(
        render(UNICODE, CommitKind::Block, commit.count, anchor),
        "\u{27ea}block \u{d7}1 \u{b7}1c69\u{27eb}"
    );
    assert_eq!(
        render(ASCII, CommitKind::Block, commit.count, anchor),
        "[... block x1 1c69 ...]"
    );
}

#[test]
fn a_block_group_of_three_two_unit_copies_renders_two_omitted_copies() {
    let span = line_span(6, 20);
    let units = split_span(&span);
    let anchor = &span[removal_range(&units, 0..2)];
    let commit = commit_of(&units, Proposal::repeat(0..6, 2, CommitKind::Block));
    assert_eq!(commit.count, 2);
    assert_eq!(commit.members(), 6);
    assert_eq!(commit.anchor.len(), 2 * 20 + 2);
    assert_eq!(
        render(UNICODE, CommitKind::Block, commit.count, anchor),
        "\u{27ea}block \u{d7}2 \u{b7}0e13\u{27eb}"
    );
    assert_eq!(
        render(ASCII, CommitKind::Block, commit.count, anchor),
        "[... block x2 0e13 ...]"
    );
}

#[test]
fn the_gate_prices_the_width_of_the_emitted_omitted_count() {
    let ten = split_span(&line_span(10, 1));
    let ten_commit = commit_of(&ten, Proposal::run(0..10, CommitKind::ExactRun));
    assert_eq!(ten_commit.count, 9);
    assert_eq!(ten_commit.anchor.len(), 1);
    assert_eq!(ten_commit.removed.len(), 10 + 2 * 9);
    assert_eq!(marker_len(UNICODE, CommitKind::ExactRun, 9), 26);
    assert!(!profitable(UNICODE, CommitKind::ExactRun, 9, 1, 27));
    assert!(profitable(UNICODE, CommitKind::ExactRun, 9, 1, 28));
    assert!(!profitable(UNICODE, CommitKind::ExactRun, 10, 1, 28));
    let eleven = split_span(&line_span(11, 1));
    let eleven_commit = commit_of(&eleven, Proposal::run(0..11, CommitKind::ExactRun));
    assert_eq!(eleven_commit.count, 10);
    assert_eq!(eleven_commit.anchor.len(), 1);
    assert_eq!(eleven_commit.removed.len(), 11 + 2 * 10);
    assert_eq!(marker_len(UNICODE, CommitKind::ExactRun, 10), 27);
    assert!(!profitable(UNICODE, CommitKind::ExactRun, 10, 1, 28));
    assert!(profitable(UNICODE, CommitKind::ExactRun, 10, 1, 29));
    assert_eq!(
        marker_len(UNICODE, CommitKind::ExactRun, 10)
            - marker_len(UNICODE, CommitKind::ExactRun, 9),
        1
    );
    assert_eq!(
        render(UNICODE, CommitKind::ExactRun, ten_commit.count, b"x").len() + 1,
        render(UNICODE, CommitKind::ExactRun, eleven_commit.count, b"x").len()
    );
}

#[test]
fn earlier_stage_ownership_blocks_later_overlaps() {
    let units = split_span(&line_span(6, 40));
    let mut ledger = ledger(&units);
    committed(ledger.try_commit(Proposal::run(2..5, CommitKind::ExactRun)));
    assert!(!ledger.is_free(2..5));
    assert!(ledger.is_free(0..2));
    assert!(ledger.is_free(5..6));
    assert!(!ledger.is_free(1..3));
    assert!(!ledger.is_free(3..6));
    assert!(!ledger.is_free(0..7));
    assert!(!ledger.is_free(2..2));
    for group in [0..3, 2..4, 4..6, 1..6, 0..6] {
        let outcome = ledger.try_commit(Proposal::run(group.clone(), CommitKind::TemplateGroup));
        assert_eq!(outcome, CommitOutcome::Overlapped, "group {group:?}");
    }
    for index in 2..5 {
        assert!(ledger.is_committed(index));
    }
    assert!(!ledger.is_committed(0));
    assert!(!ledger.is_committed(5));
    assert_eq!(ledger.commits().len(), 1);
    assert_eq!(
        ledger
            .residual()
            .map(|(index, _)| index)
            .collect::<Vec<_>>(),
        [0, 1, 5]
    );
}

#[test]
fn adjacent_commits_do_not_overlap() {
    let units = split_span(&line_span(4, 40));
    let mut ledger = ledger(&units);
    let first = committed(ledger.try_commit(Proposal::run(0..2, CommitKind::ExactRun)));
    let second = committed(ledger.try_commit(Proposal::run(2..4, CommitKind::WsRun)));
    assert!(first.removed.end <= second.removed.start);
    assert_eq!(ledger.commits(), [first, second]);
    assert_eq!(ledger.residual().count(), 0);
}

#[test]
fn ineligible_units_are_never_committed() {
    let mut records = vec![MAX_RECORD_BYTES + 1, 200, 200, 200];
    records.extend(std::iter::repeat_n(&200, 400));
    let span = dump(&records);
    let units = split_span(&span);
    assert_eq!(units.len(), records.len());
    assert!(!units[0].eligible);
    assert!(units[1].eligible);
    let mut ledger = ledger(&units);
    assert_eq!(
        ledger.try_commit(Proposal::run(0..2, CommitKind::ExactRun)),
        CommitOutcome::Ineligible
    );
    assert_eq!(
        ledger.try_commit(Proposal::run(0..4, CommitKind::ExactRun)),
        CommitOutcome::Ineligible
    );
    committed(ledger.try_commit(Proposal::run(1..4, CommitKind::ExactRun)));
    assert_eq!(ledger.commits().len(), 1);
    assert!(!ledger.is_committed(0));
    assert!(ledger.is_free(0..1));
    assert!(!ledger.is_free(0..2));
}

#[test]
fn invalid_groups_and_anchors_are_rejected() {
    let units = split_span(&line_span(3, 40));
    let mut ledger = ledger(&units);
    assert_eq!(
        ledger.try_commit(Proposal::run(1..1, CommitKind::ExactRun)),
        CommitOutcome::InvalidGroup
    );
    assert_eq!(
        ledger.try_commit(Proposal::run(2..4, CommitKind::ExactRun)),
        CommitOutcome::InvalidGroup
    );
    assert_eq!(
        ledger.try_commit(Proposal::new(0..3, 0, 3, CommitKind::ExactRun)),
        CommitOutcome::InvalidAnchor
    );
    assert_eq!(
        ledger.try_commit(Proposal::new(0..3, 4, 3, CommitKind::ExactRun)),
        CommitOutcome::InvalidAnchor
    );
    assert_eq!(
        ledger.try_commit(Proposal::new(0..3, 1, 0, CommitKind::ExactRun)),
        CommitOutcome::InvalidCount
    );
    assert_eq!(
        ledger.try_commit(Proposal::repeat(0..3, 0, CommitKind::Block)),
        CommitOutcome::InvalidAnchor
    );
    assert_eq!(
        ledger.try_commit(Proposal::repeat(0..3, 3, CommitKind::Block)),
        CommitOutcome::InvalidCount
    );
    assert_eq!(ledger.commits().len(), 0);
    assert!(!ledger.is_free(0..4));
    assert!(ledger.is_free(0..3));
}

#[test]
fn marker_style_must_be_resolved_before_committing() {
    let units = split_span(&line_span(2, 10));
    let resolved = Ledger::new(&units, UNICODE);
    assert_eq!(resolved.marker_style(), UNICODE);
    assert_eq!(resolved.units().len(), units.len());
    assert_eq!(resolved.commits().len(), 0);
}

#[test]
#[should_panic(expected = "the caller resolves Auto before committing")]
fn auto_marker_style_is_refused() {
    let units = split_span(&line_span(2, 10));
    let _ = Ledger::new(&units, MarkerStyle::Auto);
}

#[test]
#[should_panic(expected = "units must be ascending and disjoint")]
fn removal_range_asserts_its_precondition_on_non_ascending_units() {
    let units = vec![
        Unit {
            range: 0..4,
            eligible: true,
        },
        Unit {
            range: 2..6,
            eligible: true,
        },
    ];
    let _ = removal_range(&units, 0..2);
}

#[test]
#[should_panic(expected = "group must index a non-empty run of units")]
fn removal_range_asserts_its_precondition_on_out_of_bounds_groups() {
    let units = vec![Unit {
        range: 0..4,
        eligible: true,
    }];
    let _ = removal_range(&units, 0..2);
}

#[test]
fn every_commit_keeps_the_removal_invariant() {
    let mut mixed = Vec::new();
    for index in 0..6 {
        if index > 0 {
            mixed.extend_from_slice(if index % 2 == 0 { br"\n" } else { br"\u000A" });
        }
        mixed.extend(std::iter::repeat_n(b'a' + index as u8, 40));
    }
    mixed.extend_from_slice(br"\n");
    mixed.extend_from_slice(&dump(&vec![200; 406]));
    for span in [dump(&vec![200; 406]), mixed] {
        let units = split_span(&span);
        let mut ledger = ledger(&units);
        let mut attempted = 0;
        for group in [0..1, 0..3, 3..5, 1..3, units.len() - 2..units.len()] {
            attempted += 1;
            let outcome =
                ledger.try_commit(Proposal::run(group.clone(), CommitKind::TemplateGroup));
            if let CommitOutcome::Committed(commit) = outcome {
                assert_removal_invariant(&units, &group, &commit.removed.clone());
                assert_removal_invariant(
                    &units,
                    &(commit.first..commit.first + 1),
                    &commit.anchor.clone(),
                );
                assert!(profitable(
                    UNICODE,
                    commit.kind,
                    commit.count,
                    commit.anchor.len(),
                    commit.removed.len()
                ));
            }
        }
        assert_eq!(attempted, 5);
        assert!(!ledger.commits().is_empty());
        assert!(
            ledger
                .commits()
                .windows(2)
                .all(|pair| { pair[0].removed.end <= pair[1].removed.start })
        );
        for commit in ledger.commits() {
            assert!(!ledger.is_free(commit.first..commit.last + 1));
        }
    }
}

#[test]
fn stage_stats_counters_are_plain_per_detector_data() {
    let mut stats = StageStats::default();
    assert_eq!(
        stats,
        StageStats {
            groups_collapsed: 0,
            exact_runs: 0,
            ws_runs: 0,
            block_repeats: 0,
            template_groups: 0,
            templated_blocks: 0,
            record_splits: 0,
        }
    );
    for kind in [
        CommitKind::ExactRun,
        CommitKind::WsRun,
        CommitKind::Block,
        CommitKind::TemplateGroup,
        CommitKind::TemplatedBlock,
    ] {
        stats.bump(kind);
    }
    stats.record_splits += 2;
    assert_eq!(stats.groups_collapsed, 5);
    assert_eq!(stats.exact_runs, 1);
    assert_eq!(stats.ws_runs, 1);
    assert_eq!(stats.block_repeats, 1);
    assert_eq!(stats.template_groups, 1);
    assert_eq!(stats.templated_blocks, 1);
    assert_eq!(stats.record_splits, 2);
    let mut merged = stats;
    merged.merge(&stats);
    assert_eq!(merged.groups_collapsed, 10);
    assert_eq!(merged.exact_runs, 2);
    assert_eq!(merged.ws_runs, 2);
    assert_eq!(merged.block_repeats, 2);
    assert_eq!(merged.template_groups, 2);
    assert_eq!(merged.templated_blocks, 2);
    assert_eq!(merged.record_splits, 4);
}

#[test]
fn stage_stats_from_ledger_commits_cover_every_detector() {
    let units = split_span(&line_span(8, 40));
    let mut ledger = ledger(&units);
    let mut stats = StageStats::default();
    for (group, kind) in [
        (0..2, CommitKind::ExactRun),
        (2..4, CommitKind::WsRun),
        (4..6, CommitKind::Block),
        (6..8, CommitKind::TemplateGroup),
    ] {
        stats.bump(committed(ledger.try_commit(Proposal::new(group, 1, 1, kind))).kind);
    }
    assert_eq!(stats.groups_collapsed, 4);
    assert_eq!(stats.exact_runs, 1);
    assert_eq!(stats.ws_runs, 1);
    assert_eq!(stats.block_repeats, 1);
    assert_eq!(stats.template_groups, 1);
    assert_eq!(stats.templated_blocks, 0);
    stats.bump(CommitKind::TemplatedBlock);
    assert_eq!(stats.templated_blocks, 1);
    assert_eq!(stats.groups_collapsed, 5);
}

#[test]
fn ledger_path_has_no_forbidden_determinism_inputs() {
    let source = include_str!("../src/ledger.rs");
    for banned in [
        "HashMap",
        "RandomState",
        "BTreeMap",
        "SystemTime",
        "Instant",
        "std::env",
        "rand",
        "f32",
        "f64",
        "sort_by",
        "sort_unstable",
    ] {
        assert!(!source.contains(banned), "ledger must not use {banned}");
    }
}
