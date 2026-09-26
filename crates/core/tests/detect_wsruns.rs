use quantification_core::config::{MAX_LINE_BYTES, MAX_RECORD_BYTES, MarkerStyle};
use quantification_core::detect::exact::exact_runs;
use quantification_core::detect::wsruns::{Scratch, ws_runs};
use quantification_core::ledger::{
    Commit, CommitKind, CommitOutcome, Ledger, Proposal, StageStats, marker_len, profitable,
};
use quantification_core::render::render;
use quantification_core::stage1::{Unit, split_span};
use quantification_core::wsnorm::normalize;

const UNICODE: MarkerStyle = MarkerStyle::Unicode;
const TAB: &[u8] = br"INFO hc\t10.0.0.1 ok 0123456789";
const SPACES: &[u8] = br"INFO hc     10.0.0.1 ok 0123456789";
const MIXED: &[u8] = br"INFO hc \t  10.0.0.1 ok 0123456789";
const PLAIN: &[u8] = br"INFO hc 10.0.0.1 ok 0123456789";

fn new_ledger<'a>(units: &'a [Unit]) -> Ledger<'a> {
    Ledger::new(units, UNICODE)
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

fn record(len: usize, pad: &[u8]) -> Vec<u8> {
    let mut bytes = vec![b'{'];
    bytes.extend(std::iter::repeat_n(b'a', len - 2 - pad.len()));
    bytes.extend_from_slice(pad);
    bytes.push(b'}');
    bytes
}

fn padded_record(len: usize, carriage: bool) -> Vec<u8> {
    record(len, if carriage { br"\r" } else { br"\t" })
}

fn dump(records: &[Vec<u8>]) -> Vec<u8> {
    let mut span = vec![b'['];
    for (index, unit) in records.iter().enumerate() {
        if index > 0 {
            span.push(b',');
        }
        span.extend_from_slice(unit);
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

const PADS: [&str; 4] = ["\\t", "  ", " \\t ", "\\t\\t"];

fn generated_span(lines: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    let mut span = Vec::new();
    for index in 0..lines {
        if index > 0 {
            span.extend_from_slice(br"\n");
        }
        span.extend_from_slice(
            format!(
                r"2026-08-26T10:00:0{}Z INFO hc 10.0.0.{} ok{} padded payload",
                rng.below(3),
                rng.below(2),
                PADS[rng.below(PADS.len())]
            )
            .as_bytes(),
        );
    }
    span
}

#[test]
fn padded_duplicates_that_stage_three_never_sees() {
    let lines: [&[u8]; 4] = [TAB, SPACES, MIXED, PLAIN];
    let span = span_with(br"\n", &lines);
    let units = split_span(&span);
    assert_eq!(units.len(), 4);
    assert_ne!(TAB, SPACES);
    assert_ne!(TAB.len(), SPACES.len());
    assert_eq!(normalize(TAB), normalize(SPACES));
    assert_eq!(normalize(MIXED), normalize(PLAIN));
    let mut raw = new_ledger(&units);
    let mut scratch = Scratch::default();
    assert_eq!(exact_runs(&span, &mut raw, 3), StageStats::default());
    assert_eq!(raw.commits().len(), 0);
    let mut ledger = new_ledger(&units);
    let stats = ws_runs(&span, &mut ledger, 3, &mut scratch);
    assert_eq!(stats.ws_runs, 1);
    assert_eq!(stats.groups_collapsed, 1);
    assert_eq!(stats.exact_runs, 0);
    assert_eq!(ledger.commits().len(), 1);
    let commit = &ledger.commits()[0];
    assert_eq!(commit.kind, CommitKind::WsRun);
    assert_eq!((commit.first, commit.last, commit.count), (0, 3, 3));
    assert_eq!(commit.anchor, units[0].range.clone());
    assert_eq!(
        commit.removed.len(),
        TAB.len() + SPACES.len() + MIXED.len() + PLAIN.len() + 2 * 3
    );
    assert_eq!(marker_len(UNICODE, CommitKind::WsRun, commit.count), 31);
    assert_removal_invariant(&units, commit);
    assert_eq!(ledger.residual().count(), 0);
}

#[test]
fn the_anchor_is_the_raw_original_bytes() {
    let lines: [&[u8]; 3] = [TAB, SPACES, MIXED];
    let span = span_with(br"\n", &lines);
    let units = split_span(&span);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    assert_eq!(ws_runs(&span, &mut ledger, 3, &mut scratch).ws_runs, 1);
    let anchor = &span[ledger.commits()[0].anchor.clone()];
    assert_eq!(anchor, TAB);
    assert_ne!(anchor, &normalize(TAB)[..]);
    assert_eq!(normalize(anchor), normalize(SPACES));
    assert_eq!(
        render(UNICODE, CommitKind::WsRun, 2, anchor).len(),
        marker_len(UNICODE, CommitKind::WsRun, 2)
    );
}

#[test]
fn stage_four_commits_only_what_stage_three_left_on_the_residual() {
    let exact = vec![b'p'; 40];
    let mut lines: Vec<&[u8]> = vec![&exact; 3];
    lines.extend([TAB, SPACES, MIXED]);
    let span = span_with(br"\n", &lines);
    let units = split_span(&span);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    let first = exact_runs(&span, &mut ledger, 3);
    assert_eq!(first.exact_runs, 1);
    let second = ws_runs(&span, &mut ledger, 3, &mut scratch);
    assert_eq!(second.ws_runs, 1);
    assert_eq!(ledger.commits().len(), 2);
    assert_eq!(
        ledger
            .commits()
            .iter()
            .map(|commit| (commit.kind, commit.first, commit.last))
            .collect::<Vec<_>>(),
        [(CommitKind::ExactRun, 0, 2), (CommitKind::WsRun, 3, 5)]
    );
    assert!(ledger.commits()[1].first > ledger.commits()[0].last);
    for commit in ledger.commits() {
        assert_removal_invariant(&units, commit);
    }
}

#[test]
fn min_group_size_bounds_the_smallest_ws_group() {
    let span = span_with(br"\n", &[TAB, SPACES]);
    let units = split_span(&span);
    let mut scratch = Scratch::default();
    let mut ledger = new_ledger(&units);
    assert_eq!(
        ws_runs(&span, &mut ledger, 3, &mut scratch),
        StageStats::default()
    );
    assert_eq!(ledger.commits().len(), 0);
    let mut ledger = new_ledger(&units);
    let stats = ws_runs(&span, &mut ledger, 2, &mut scratch);
    assert_eq!(stats.ws_runs, 1);
    let commit = &ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (0, 1, 1));
    assert_eq!(render(UNICODE, commit.kind, commit.count, TAB).len(), 31);
    let triple = span_with(br"\n", &[TAB, SPACES, MIXED]);
    let units = split_span(&triple);
    let mut ledger = new_ledger(&units);
    assert_eq!(
        ws_runs(&triple, &mut ledger, 4, &mut scratch),
        StageStats::default()
    );
    assert_eq!(ledger.commits().len(), 0);
    assert_eq!(ledger.residual().count(), 3);
}

#[test]
fn a_below_threshold_ws_run_stays_verbatim_and_remains_free() {
    let narrow: [&[u8]; 3] = [br"a\tb\tc", br"a  b  c", br"a\t\tb c"];
    let span = span_with(br"\n", &narrow);
    let units = split_span(&span);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    assert_eq!(
        ws_runs(&span, &mut ledger, 3, &mut scratch),
        StageStats::default()
    );
    assert!(!profitable(UNICODE, CommitKind::WsRun, 2, 7, 7 + 7 + 8 + 4));
    assert!(ledger.is_free(0..3));
    assert_eq!(
        ledger
            .residual()
            .map(|(index, _)| index)
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert_eq!(
        ws_runs(&span, &mut ledger, 3, &mut scratch),
        StageStats::default()
    );
    let wide: [&[u8]; 3] = [TAB, SPACES, MIXED];
    let span = span_with(br"\n", &wide);
    let units = split_span(&span);
    let mut ledger = new_ledger(&units);
    assert_eq!(ws_runs(&span, &mut ledger, 3, &mut scratch).ws_runs, 1);
    assert_eq!(ledger.commits()[0].first, 0);
    assert!(profitable(
        UNICODE,
        CommitKind::WsRun,
        2,
        TAB.len(),
        TAB.len() + SPACES.len() + MIXED.len() + 4
    ));
}

#[test]
fn an_over_cap_record_wall_splits_ws_runs() {
    let mut records: Vec<Vec<u8>> = (0..200).map(|i| padded_record(200, i % 2 == 0)).collect();
    records.push(record(MAX_RECORD_BYTES + 1, br"\t"));
    records.extend((0..200).map(|i| padded_record(200, i % 3 == 0)));
    let span = dump(&records);
    assert!(span.len() > MAX_LINE_BYTES);
    let units = split_span(&span);
    assert_eq!(units.len(), 401);
    let wall = 200;
    assert!(!units[wall].eligible);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    let mut exact = new_ledger(&units);
    assert_eq!(exact_runs(&span, &mut exact, 3), StageStats::default());
    let stats = ws_runs(&span, &mut ledger, 3, &mut scratch);
    assert_eq!(stats.ws_runs, 2);
    assert_eq!(
        ledger
            .commits()
            .iter()
            .map(|commit| (commit.first, commit.last, commit.count))
            .collect::<Vec<_>>(),
        [(1, 199, 198), (201, 399, 198)]
    );
    assert!(!ledger.is_committed(wall));
    assert!(ledger.is_free(wall..wall + 1));
    assert!(!ledger.is_committed(0));
    assert!(!ledger.is_committed(400));
    for commit in ledger.commits() {
        assert_removal_invariant(&units, commit);
        assert!(commit.first > wall || commit.last < wall);
        assert_eq!(commit.removed.len(), 199 * 200 + 198);
    }
    assert_eq!(ledger.residual().count(), 3);
}

#[test]
fn stage1b_records_group_in_the_ws_domain() {
    let records: Vec<Vec<u8>> = (0..400).map(|i| padded_record(200, i % 2 == 0)).collect();
    let span = dump(&records);
    let units = split_span(&span);
    assert_eq!(units.len(), 400);
    let mut exact = new_ledger(&units);
    assert_eq!(exact_runs(&span, &mut exact, 3), StageStats::default());
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    let stats = ws_runs(&span, &mut ledger, 3, &mut scratch);
    assert_eq!(stats.ws_runs, 1);
    let commit = &ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (1, 398, 397));
    assert_eq!(commit.removed.len(), 398 * 200 + 397);
    assert_eq!(&span[commit.anchor.clone()], &padded_record(200, false)[..]);
    assert_eq!(
        normalize(&span[commit.anchor.clone()]),
        normalize(&span[units[398].range.clone()])
    );
    assert!(!ledger.is_committed(0));
    assert!(!ledger.is_committed(399));
    assert_removal_invariant(&units, commit);
}

#[test]
fn a_ws_run_never_straddles_a_committed_exact_run() {
    let base: &[u8] = br"payload 0123456789abcdefghij";
    let mut lines: Vec<Vec<u8>> = Vec::new();
    for pad in ["\\t", "  ", " \\t ", " \\t ", "\\t\\t"] {
        let mut line = b"INFO hc".to_vec();
        line.extend_from_slice(pad.as_bytes());
        line.extend_from_slice(base);
        lines.push(line);
    }
    let borrowed: Vec<&[u8]> = lines.iter().map(|line| line.as_slice()).collect();
    let span = span_with(br"\n", &borrowed);
    let units = split_span(&span);
    assert_eq!(units.len(), 5);
    assert_eq!(&lines[2], &lines[3]);
    assert_ne!(&lines[0], &lines[2]);
    assert_eq!(
        normalize(&span[units[0].range.clone()]),
        normalize(&span[units[4].range.clone()])
    );
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    let stats = exact_runs(&span, &mut ledger, 2);
    assert_eq!(stats.exact_runs, 1);
    assert_eq!(
        ledger
            .commits()
            .iter()
            .map(|commit| (commit.first, commit.last))
            .collect::<Vec<_>>(),
        [(2, 3)]
    );
    let stats = ws_runs(&span, &mut ledger, 2, &mut scratch);
    assert_eq!(stats.ws_runs, 1);
    assert_eq!(
        ledger
            .commits()
            .iter()
            .map(|commit| (commit.kind, commit.first, commit.last))
            .collect::<Vec<_>>(),
        [(CommitKind::WsRun, 0, 1), (CommitKind::ExactRun, 2, 3)]
    );
    assert!(!ledger.is_committed(4));
    assert_eq!(ledger.residual().count(), 1);
    for commit in ledger.commits() {
        assert_removal_invariant(&units, commit);
    }
    let mut only_two = new_ledger(&units);
    let mut scratch = Scratch::default();
    assert!(matches!(
        only_two.try_commit(Proposal::run(2..4, CommitKind::ExactRun)),
        CommitOutcome::Committed(_)
    ));
    assert_eq!(ws_runs(&span, &mut only_two, 2, &mut scratch).ws_runs, 1);
    assert_eq!(only_two.commits().len(), 2);
}

#[test]
fn edge_padding_collapses_to_the_same_form() {
    let forms: [&[u8]; 4] = [
        br"  INFO hc\tpad ok  ",
        br"INFO hc  pad ok",
        br" INFO hc\t\tpad ok ",
        br"INFO hc \t pad ok\t",
    ];
    for form in forms {
        assert_eq!(normalize(form), b"INFO hc pad ok", "form {form:?}");
    }
    let span = span_with(br"\n", &forms);
    let units = split_span(&span);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    assert_eq!(ws_runs(&span, &mut ledger, 3, &mut scratch).ws_runs, 1);
    let commit = &ledger.commits()[0];
    assert_eq!(&span[commit.anchor.clone()], br"  INFO hc\tpad ok  ");
    assert_removal_invariant(&units, commit);
    let single = span_with(br"\n", &[br"  INFO hc\tpad ok  "]);
    let units = split_span(&single);
    let mut ledger = new_ledger(&units);
    assert_eq!(
        ws_runs(&single, &mut ledger, 3, &mut scratch),
        StageStats::default()
    );
}

#[test]
fn the_scratch_buffer_is_reused_and_never_grows_with_the_line_count() {
    let few = span_with(br"\n", &[TAB, TAB, SPACES, SPACES]);
    let many: Vec<Vec<u8>> = (0..2000)
        .map(|i| {
            let mut line = b"INFO hc".to_vec();
            line.extend_from_slice(if i % 2 == 0 { br"\t" } else { br"\r" });
            line.extend_from_slice(br"10.0.0.1 ok 0123456789");
            line
        })
        .collect();
    let borrowed: Vec<&[u8]> = many.iter().map(|line| line.as_slice()).collect();
    let many_span = span_with(br"\n", &borrowed);
    let units = split_span(&many_span);
    let widest = units.iter().map(|unit| unit.range.len()).max().unwrap();
    let mut scratch = Scratch::with_capacity(widest, widest);
    let mut ledger = new_ledger(&units);
    let stats = ws_runs(&many_span, &mut ledger, 3, &mut scratch);
    assert_eq!(stats.ws_runs, 1);
    assert_eq!(scratch.reserved(), (widest, widest));
    let few_units = split_span(&few);
    let mut few_ledger = new_ledger(&few_units);
    assert_eq!(ws_runs(&few, &mut few_ledger, 3, &mut scratch).ws_runs, 1);
    assert_eq!(scratch.reserved(), (widest, widest));
    let mut grown = Scratch::default();
    let mut grown_ledger = new_ledger(&units);
    assert_eq!(ws_runs(&many_span, &mut grown_ledger, 3, &mut grown), stats);
    assert!(grown.reserved().0 <= 2 * widest);
    assert!(grown.reserved().1 <= 2 * widest);
    assert_eq!(grown_ledger.commits(), ledger.commits());
}

#[test]
fn ws_runs_is_deterministic() {
    let span = generated_span(400, 0x5eed_1234_abcd_0303);
    let units = split_span(&span);
    let mut first = new_ledger(&units);
    let mut second = new_ledger(&units);
    let mut scratch = Scratch::default();
    let stats = ws_runs(&span, &mut first, 3, &mut scratch);
    let mut other = Scratch::with_capacity(0, 0);
    assert_eq!(ws_runs(&span, &mut second, 3, &mut other), stats);
    assert!(stats.ws_runs > 3, "the generator produced no ws runs");
    assert_eq!(first.commits(), second.commits());
    assert_eq!(apply(&span, &first), apply(&span, &second));
    for commit in first.commits() {
        assert_removal_invariant(&units, commit);
    }
    assert_eq!(
        ws_runs(&span, &mut first, 3, &mut scratch),
        StageStats::default()
    );
    assert_eq!(first.commits(), second.commits());
    let second_span = generated_span(400, 0x0f0f_0f0f_0f0f_0f0f);
    let units = split_span(&second_span);
    let mut first = new_ledger(&units);
    let mut second = new_ledger(&units);
    assert_eq!(
        ws_runs(&second_span, &mut first, 3, &mut scratch),
        ws_runs(&second_span, &mut second, 3, &mut other)
    );
    assert_eq!(apply(&second_span, &first), apply(&second_span, &second));
}

#[test]
fn empty_ineligible_and_single_unit_spans_commit_nothing() {
    let mut scratch = Scratch::default();
    let empty: &[u8] = b"";
    let empty_units = split_span(empty);
    let mut ledger = new_ledger(&empty_units);
    assert_eq!(
        ws_runs(empty, &mut ledger, 3, &mut scratch),
        StageStats::default()
    );
    let single = br"only one line";
    let single_units = split_span(single);
    let mut ledger = new_ledger(&single_units);
    assert_eq!(
        ws_runs(single, &mut ledger, 3, &mut scratch),
        StageStats::default()
    );
    let wall = vec![b'z'; MAX_LINE_BYTES + 1];
    let units = split_span(&wall);
    assert_eq!(units.len(), 1);
    assert!(!units[0].eligible);
    let mut ledger = new_ledger(&units);
    assert_eq!(
        ws_runs(&wall, &mut ledger, 3, &mut scratch),
        StageStats::default()
    );
    assert!(ledger.is_free(0..1));
}

#[test]
fn the_wsruns_module_has_no_forbidden_determinism_inputs() {
    let source = include_str!("../src/detect/wsruns.rs");
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
        assert!(!source.contains(banned), "ws runs must not use {banned}");
    }
    assert!(source.contains("normalize_into"));
}
