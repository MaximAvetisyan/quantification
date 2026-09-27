use quantification_core::config::{MAX_LINE_BYTES, MAX_RECORD_BYTES, MarkerStyle};
use quantification_core::detect::exact::exact_runs;
use quantification_core::ledger::{
    Commit, CommitKind, CommitOutcome, Ledger, Proposal, StageStats, marker_len, profitable,
};
use quantification_core::render::render;
use quantification_core::stage1::{Unit, split_span};

const UNICODE: MarkerStyle = MarkerStyle::Unicode;

fn new_ledger<'a>(units: &'a [Unit]) -> Ledger<'a> {
    Ledger::new(units, UNICODE)
}

fn line_span(count: usize, len: usize) -> Vec<u8> {
    let mut span = Vec::new();
    for index in 0..count {
        if index > 0 {
            span.extend_from_slice(br"\n");
        }
        span.extend(std::iter::repeat_n(b'x', len));
    }
    span
}

fn span_with(sep: &[u8], lines: &[&[u8]]) -> Vec<u8> {
    let mut span = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            span.extend_from_slice(sep);
        }
        span.extend_from_slice(line);
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
    for (index, len) in records.iter().enumerate() {
        if index > 0 {
            span.push(b',');
        }
        span.extend_from_slice(&record(*len));
    }
    span.push(b']');
    span
}

fn apply(span: &[u8], ledger: &Ledger<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut at = 0;
    for commit in ledger.commits() {
        out.extend_from_slice(&span[at..commit.anchor.start]);
        out.extend_from_slice(&span[commit.anchor.clone()]);
        out.extend_from_slice(&render(
            ledger.marker_style(),
            commit.kind,
            commit.count,
            &span[commit.anchor.clone()],
        ));
        at = commit.removed.end;
    }
    out.extend_from_slice(&span[at..]);
    out
}

fn assert_removal_invariant(units: &[Unit], commit: &Commit) {
    let members = &units[commit.first..commit.last + 1];
    let gaps: usize = members
        .windows(2)
        .map(|pair| pair[1].range.start - pair[0].range.end)
        .sum();
    let member_bytes: usize = members.iter().map(|unit| unit.range.len()).sum();
    assert_eq!(
        commit.removed,
        members[0].range.start..members[members.len() - 1].range.end
    );
    assert_eq!(commit.removed.len(), member_bytes + gaps);
    assert_eq!(commit.anchor.len(), units[commit.first].range.len());
    assert!(commit.anchor.start >= commit.removed.start);
    assert!(commit.anchor.end <= commit.removed.end);
    assert!(profitable(
        UNICODE,
        commit.kind,
        commit.count,
        commit.anchor.len(),
        commit.removed.len()
    ));
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn generated_span(lines: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    let mut span = Vec::new();
    for index in 0..lines {
        if index > 0 {
            span.extend_from_slice(br"\n");
        }
        span.extend_from_slice(
            format!(
                r"2026-08-26T10:00:0{}Z INFO hc 10.0.0.{} ok padded payload",
                rng.below(3),
                rng.below(2)
            )
            .as_bytes(),
        );
    }
    span
}

#[test]
fn a_raw_identical_run_commits_one_exact_run() {
    let span = line_span(5, 40);
    let units = split_span(&span, UNICODE);
    let mut ledger = new_ledger(&units);
    let stats = exact_runs(&span, &mut ledger, 3);
    assert_eq!(stats.exact_runs, 1);
    assert_eq!(stats.groups_collapsed, 1);
    assert_eq!(stats.ws_runs, 0);
    assert_eq!(ledger.commits().len(), 1);
    let commit = &ledger.commits()[0];
    assert_eq!(commit.kind, CommitKind::ExactRun);
    assert_eq!((commit.first, commit.last, commit.count), (0, 4, 4));
    assert_eq!(commit.anchor, units[0].range.clone());
    assert_eq!(commit.removed, 0..208);
    assert_eq!(commit.removed.len(), 5 * 40 + 2 * 4);
    assert_eq!(marker_len(UNICODE, CommitKind::ExactRun, commit.count), 26);
    assert_removal_invariant(&units, commit);
    assert_eq!(ledger.residual().count(), 0);
}

#[test]
fn below_threshold_runs_stay_verbatim_and_do_not_block_the_next_run() {
    let mut lines: Vec<Vec<u8>> = vec![vec![b'x'; 4]; 3];
    lines.extend(vec![vec![b'y'; 40]; 3]);
    let borrowed: Vec<&[u8]> = lines.iter().map(|line| line.as_slice()).collect();
    let span = span_with(br"\n", &borrowed);
    let units = split_span(&span, UNICODE);
    let mut ledger = new_ledger(&units);
    let stats = exact_runs(&span, &mut ledger, 3);
    assert_eq!(stats.exact_runs, 1);
    assert_eq!(ledger.commits().len(), 1);
    let commit = &ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (3, 5, 2));
    assert!(!profitable(UNICODE, CommitKind::ExactRun, 2, 4, 3 * 4 + 4));
    assert!(ledger.is_free(0..3));
    assert_eq!(
        ledger
            .residual()
            .map(|(index, _)| index)
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert_eq!(exact_runs(&span, &mut ledger, 3), StageStats::default());
    let lines: Vec<Vec<u8>> = vec![vec![b'x'; 20]; 3];
    let borrowed: Vec<&[u8]> = lines.iter().map(|line| line.as_slice()).collect();
    let wide = span_with(br"\n", &borrowed);
    let units = split_span(&wide, UNICODE);
    let mut ledger = new_ledger(&units);
    let stats = exact_runs(&wide, &mut ledger, 3);
    assert_eq!(stats.exact_runs, 1);
    assert_eq!(ledger.commits()[0].first, 0);
    assert!(profitable(UNICODE, CommitKind::ExactRun, 2, 20, 3 * 20 + 4));
}

#[test]
fn the_raw_domain_does_not_merge_padding_variants() {
    let padded: &[u8] = br"INFO hc\t10.0.0.1 ok x";
    let plain: &[u8] = br"INFO hc 10.0.0.1 ok x";
    assert_ne!(padded, plain);
    assert_ne!(padded.len(), plain.len());
    let mut lines: Vec<&[u8]> = vec![padded; 3];
    lines.extend(vec![plain; 3]);
    let span = span_with(br"\n", &lines);
    let units = split_span(&span, UNICODE);
    let mut ledger = new_ledger(&units);
    let stats = exact_runs(&span, &mut ledger, 3);
    assert_eq!(stats.exact_runs, 2);
    let groups: Vec<(usize, usize)> = ledger
        .commits()
        .iter()
        .map(|commit| (commit.first, commit.last))
        .collect();
    assert_eq!(groups, [(0, 2), (3, 5)]);
    assert_eq!(&span[ledger.commits()[0].anchor.clone()], padded);
    assert_eq!(&span[ledger.commits()[1].anchor.clone()], plain);
    for commit in ledger.commits() {
        assert_removal_invariant(&units, commit);
    }
}

#[test]
fn raw_identical_lines_commit_regardless_of_the_normalize_ws_option() {
    let padded: &[u8] = br"INFO hc\t10.0.0.1 ok 0123456789";
    let lines: [&[u8]; 4] = [padded, padded, padded, br"INFO hc 10.0.0.1 ok 0123456789"];
    let span = span_with(br"\n", &lines);
    let units = split_span(&span, UNICODE);
    let mut first = new_ledger(&units);
    let mut second = new_ledger(&units);
    let stats = exact_runs(&span, &mut first, 3);
    assert_eq!(exact_runs(&span, &mut second, 3), stats);
    assert_eq!(stats.exact_runs, 1);
    let commit = &first.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (0, 2, 2));
    assert_eq!(&span[commit.anchor.clone()], padded);
    assert_eq!(commit.removed.len(), 3 * padded.len() + 4);
    let source = include_str!("../src/detect/exact.rs");
    assert!(!source.contains("normalize_ws"));
    assert!(!source.contains("normalize"));
}

#[test]
fn the_count_width_is_priced_at_the_decimal_carry() {
    let ten = line_span(10, 1);
    let units = split_span(&ten, UNICODE);
    let mut ledger = new_ledger(&units);
    let stats = exact_runs(&ten, &mut ledger, 3);
    assert_eq!(stats.exact_runs, 1);
    let commit = &ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (0, 9, 9));
    assert_eq!(commit.removed.len(), 10 + 2 * 9);
    assert!(!profitable(UNICODE, CommitKind::ExactRun, 10, 1, 28));
    assert!(profitable(UNICODE, CommitKind::ExactRun, 9, 1, 28));
    let eleven = line_span(11, 1);
    let units = split_span(&eleven, UNICODE);
    let mut ledger = new_ledger(&units);
    let stats = exact_runs(&eleven, &mut ledger, 3);
    assert_eq!(stats.exact_runs, 1);
    let commit = &ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (0, 10, 10));
    assert_eq!(commit.removed.len(), 11 + 2 * 10);
    assert_eq!(render(UNICODE, commit.kind, commit.count, b"x").len(), 27);
    assert_eq!(
        marker_len(UNICODE, CommitKind::ExactRun, 10)
            - marker_len(UNICODE, CommitKind::ExactRun, 9),
        1
    );
}

#[test]
fn an_over_cap_record_wall_splits_runs_without_being_grouped() {
    let mut records = vec![200; 200];
    records.push(MAX_RECORD_BYTES + 1);
    records.extend(std::iter::repeat_n(&200, 200));
    let span = dump(&records);
    assert!(span.len() > MAX_LINE_BYTES);
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), 401);
    let wall = 200;
    assert!(!units[wall].eligible);
    assert!(units[0].eligible && units[400].eligible);
    let mut ledger = new_ledger(&units);
    let stats = exact_runs(&span, &mut ledger, 3);
    assert_eq!(stats.exact_runs, 2);
    let groups: Vec<(usize, usize, u64)> = ledger
        .commits()
        .iter()
        .map(|commit| (commit.first, commit.last, commit.count))
        .collect();
    assert_eq!(groups, [(1, 199, 198), (201, 399, 198)]);
    assert!(!ledger.is_committed(wall));
    assert!(ledger.is_free(wall..wall + 1));
    assert!(!ledger.is_committed(0));
    assert!(!ledger.is_committed(400));
    for commit in ledger.commits() {
        assert_removal_invariant(&units, commit);
        assert!(commit.first > wall || commit.last < wall);
        assert_eq!(commit.removed.len(), 199 * 200 + 198);
        assert_eq!(&span[commit.anchor.clone()], &record(200)[..]);
    }
    assert_eq!(ledger.residual().count(), 3);
}

#[test]
fn stage1b_records_group_in_the_raw_domain() {
    let span = dump(&vec![200; 400]);
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), 400);
    assert!(span[units[0].range.clone()].starts_with(b"[{"));
    assert!(span[units[399].range.clone()].ends_with(b"}]"));
    let mut ledger = new_ledger(&units);
    let stats = exact_runs(&span, &mut ledger, 3);
    assert_eq!(stats.exact_runs, 1);
    let commit = &ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (1, 398, 397));
    assert_eq!(commit.removed.len(), 398 * 200 + 397);
    assert_eq!(&span[commit.anchor.clone()], &record(200)[..]);
    let mut expected = Vec::new();
    for index in 0..398 {
        if index > 0 {
            expected.push(b',');
        }
        expected.extend_from_slice(&record(200));
    }
    assert_eq!(&span[commit.removed.clone()], &expected[..]);
    assert_eq!(&span[commit.removed.end..units[399].range.start], b",");
    assert!(!ledger.is_committed(0));
    assert!(!ledger.is_committed(399));
}

#[test]
fn the_removal_rule_covers_line_and_record_joiners_in_one_span() {
    let first = vec![b'a'; 40];
    let second = vec![b'b'; 40];
    let mut span = span_with(br"\n", &[&first, &first, &first]);
    span.extend_from_slice(br"\u000A");
    span.extend_from_slice(&span_with(br"\u000A", &[&second, &second, &second]));
    span.extend_from_slice(br"\n");
    span.extend_from_slice(&dump(&vec![200; 400]));
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), 6 + 400);
    let mut ledger = new_ledger(&units);
    let stats = exact_runs(&span, &mut ledger, 3);
    assert_eq!(stats.exact_runs, 3);
    assert_eq!(
        ledger
            .commits()
            .iter()
            .map(|commit| commit.removed.len())
            .collect::<Vec<_>>(),
        [3 * 40 + 2 * 2, 3 * 40 + 2 * 6, 398 * 200 + 397]
    );
    assert_eq!(
        &span[ledger.commits()[0].removed.end..ledger.commits()[1].removed.start],
        br"\u000A"
    );
    assert_eq!(
        &span[ledger.commits()[1].removed.end..units[6].range.start],
        br"\n"
    );
    let mut head_gap = span[units[6].range.clone()].to_vec();
    head_gap.push(b',');
    assert_eq!(
        &span[units[6].range.start..ledger.commits()[2].removed.start],
        &head_gap[..]
    );
    assert!(!ledger.is_committed(6));
    for commit in ledger.commits() {
        assert_removal_invariant(&units, commit);
        assert_eq!(commit.kind, CommitKind::ExactRun);
    }
}

#[test]
fn leftmost_first_discovery_in_anchor_offset_order() {
    let a = vec![b'a'; 40];
    let b = vec![b'b'; 40];
    let c = vec![b'c'; 40];
    let x = vec![b'x'; 40];
    let y = vec![b'y'; 40];
    let span = span_with(br"\n", &[&a, &a, &a, &x, &b, &b, &b, &b, &y, &c, &c, &c]);
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), 12);
    let mut ledger = new_ledger(&units);
    let stats = exact_runs(&span, &mut ledger, 3);
    assert_eq!(stats.exact_runs, 3);
    let commits = ledger.commits();
    assert_eq!(
        commits
            .iter()
            .map(|commit| (commit.first, commit.last, commit.count))
            .collect::<Vec<_>>(),
        [(0, 2, 2), (4, 7, 3), (9, 11, 2)]
    );
    assert_eq!(commits[0].anchor.start, units[0].range.start);
    assert_eq!(commits[1].anchor.start, units[4].range.start);
    assert_eq!(commits[2].anchor.start, units[9].range.start);
    assert!(
        commits
            .windows(2)
            .all(|pair| pair[0].removed.end <= pair[1].removed.start)
    );
    for commit in commits {
        assert_removal_invariant(&units, commit);
    }
}

#[test]
fn a_run_never_straddles_a_region_committed_by_an_earlier_stage() {
    let span = line_span(6, 40);
    let units = split_span(&span, UNICODE);
    let mut ledger = new_ledger(&units);
    let earlier = ledger.try_commit(Proposal::repeat(2..4, 1, CommitKind::Block));
    assert!(matches!(earlier, CommitOutcome::Committed(_)));
    let stats = exact_runs(&span, &mut ledger, 2);
    assert_eq!(stats.exact_runs, 2);
    let kinds: Vec<CommitKind> = ledger.commits().iter().map(|c| c.kind).collect();
    assert_eq!(
        kinds,
        [
            CommitKind::ExactRun,
            CommitKind::Block,
            CommitKind::ExactRun
        ]
    );
    let groups: Vec<(usize, usize)> = ledger
        .commits()
        .iter()
        .map(|commit| (commit.first, commit.last))
        .collect();
    assert_eq!(groups, [(0, 1), (2, 3), (4, 5)]);
    assert_eq!(ledger.residual().count(), 0);
    for commit in ledger.commits() {
        assert_removal_invariant(&units, commit);
    }
    let mut ledger = new_ledger(&units);
    assert!(matches!(
        ledger.try_commit(Proposal::repeat(2..4, 1, CommitKind::Block)),
        CommitOutcome::Committed(_)
    ));
    let stats = exact_runs(&span, &mut ledger, 3);
    assert_eq!(stats.exact_runs, 0);
    assert_eq!(ledger.commits().len(), 1);
    assert_eq!(
        ledger
            .residual()
            .map(|(index, _)| index)
            .collect::<Vec<_>>(),
        [0, 1, 4, 5]
    );
}

#[test]
fn min_group_size_bounds_the_smallest_group() {
    let pair = line_span(2, 40);
    let units = split_span(&pair, UNICODE);
    let mut ledger = new_ledger(&units);
    assert_eq!(exact_runs(&pair, &mut ledger, 3), StageStats::default());
    assert_eq!(ledger.commits().len(), 0);
    let mut ledger = new_ledger(&units);
    let stats = exact_runs(&pair, &mut ledger, 2);
    assert_eq!(stats.exact_runs, 1);
    let commit = &ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (0, 1, 1));
    assert_eq!(render(UNICODE, commit.kind, commit.count, b"x").len(), 26);
    let triple = line_span(3, 40);
    let units = split_span(&triple, UNICODE);
    let mut ledger = new_ledger(&units);
    assert_eq!(exact_runs(&triple, &mut ledger, 4), StageStats::default());
    assert_eq!(ledger.commits().len(), 0);
    assert_eq!(ledger.residual().count(), 3);
}

#[test]
fn empty_ineligible_and_single_unit_spans_commit_nothing() {
    let empty: &[u8] = b"";
    let empty_units = split_span(empty, UNICODE);
    let mut ledger = new_ledger(&empty_units);
    assert_eq!(exact_runs(empty, &mut ledger, 3), StageStats::default());
    let single = br"only one line";
    let single_units = split_span(single, UNICODE);
    let mut ledger = new_ledger(&single_units);
    assert_eq!(exact_runs(single, &mut ledger, 3), StageStats::default());
    assert_eq!(ledger.commits().len(), 0);
    let wall = vec![b'z'; MAX_LINE_BYTES + 1];
    let units = split_span(&wall, UNICODE);
    assert_eq!(units.len(), 1);
    assert!(!units[0].eligible);
    let mut ledger = new_ledger(&units);
    assert_eq!(exact_runs(&wall, &mut ledger, 3), StageStats::default());
    assert!(ledger.is_free(0..1));
    assert_eq!(ledger.commits().len(), 0);
}

#[test]
fn exact_runs_is_deterministic() {
    let span = generated_span(400, 0x5eed_1234_abcd_0303);
    let units = split_span(&span, UNICODE);
    let mut first = new_ledger(&units);
    let mut second = new_ledger(&units);
    let stats = exact_runs(&span, &mut first, 3);
    assert_eq!(exact_runs(&span, &mut second, 3), stats);
    assert!(stats.exact_runs > 3, "the generator produced no runs");
    assert_eq!(first.commits(), second.commits());
    assert_eq!(apply(&span, &first), apply(&span, &second));
    for commit in first.commits() {
        assert_removal_invariant(&units, commit);
    }
    assert_eq!(exact_runs(&span, &mut first, 3), StageStats::default());
    assert_eq!(first.commits(), second.commits());
    let wide = generated_span(400, 0x1111_2222_3333_4444);
    let units = split_span(&wide, UNICODE);
    let mut first = new_ledger(&units);
    let mut second = new_ledger(&units);
    assert_eq!(
        exact_runs(&wide, &mut first, 3),
        exact_runs(&wide, &mut second, 3)
    );
    assert_eq!(apply(&wide, &first), apply(&wide, &second));
}

fn uses_token(source: &str, banned: &str) -> bool {
    source
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|word| word == banned)
}

#[test]
fn the_exact_module_has_no_forbidden_determinism_inputs() {
    let source = include_str!("../src/detect/exact.rs");
    let uses = |banned: &str| uses_token(source, banned);
    assert!(
        uses_token("fn f() { rand(); }", "rand"),
        "a real use is seen"
    );
    assert!(
        uses_token("use std::collections::HashMap as Map;", "HashMap"),
        "a real use is seen"
    );
    assert!(
        uses_token("let state = RandomState::new();", "RandomState"),
        "a real use is seen"
    );
    assert!(
        uses_token("fn f() { std::env::var(\"X\"); }", "env"),
        "a real use is seen"
    );
    assert!(
        !uses_token("let brand = 1;", "rand"),
        "the scan is not a substring match"
    );
    assert!(
        !uses_token("fn f() { let brand = 1; }", "rand"),
        "the scan is not a substring match"
    );
    for banned in [
        "HashMap",
        "RandomState",
        "BTreeMap",
        "SystemTime",
        "Instant",
        "env",
        "rand",
        "f32",
        "f64",
        "sort_by",
        "sort_unstable",
    ] {
        assert!(!uses(banned), "exact runs must not use {banned}");
    }
}
