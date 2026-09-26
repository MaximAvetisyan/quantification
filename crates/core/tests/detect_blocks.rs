use quantification_core::config::{
    MAX_BLOCK_LINES, MAX_LINE_BYTES, MAX_RECORD_BYTES, MIN_BLOCK_LINES, MarkerStyle,
};
use quantification_core::detect::blocks::{Scratch, repeated_blocks};
use quantification_core::detect::exact::exact_runs;
use quantification_core::detect::wsruns::{Scratch as WsScratch, ws_runs};
use quantification_core::ledger::{
    Commit, CommitKind, CommitOutcome, Ledger, Proposal, StageStats, marker_len, profitable,
};
use quantification_core::render::render;
use quantification_core::stage1::{Unit, split_span};
use quantification_core::wsnorm::normalize;

const UNICODE: MarkerStyle = MarkerStyle::Unicode;
const H0: &[u8] = br"INFO run start trace 1 payload";
const H1: &[u8] = br"INFO phase one begin payload";
const L0: &[u8] = br"INFO hc 10.0.0.1 ok 0123456789";
const L1: &[u8] = br"INFO hc 10.0.0.2 ok 9876543210";
const L0P: &[u8] = br"INFO hc\t10.0.0.1 ok 0123456789";
const L1P: &[u8] = br"INFO hc \t 10.0.0.2 ok 9876543210";
const L0Q: &[u8] = br"INFO hc\t\t10.0.0.1 ok 0123456789";
const L1Q: &[u8] = br"INFO hc\t 10.0.0.2 ok 9876543210";
const C0: &[u8] = br"INFO hc 10.0.0.3 ok aaaabbbbcc";
const LZ: &[u8] = br"INFO hc 10.0.0.9 ok divergent!!";
const E0: &[u8] = br"INFO hc 10.0.0.7 ok 40-byte-exact-line!!";

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

fn lines_span(lines: &[&[u8]]) -> Vec<u8> {
    span_with(br"\n", lines)
}

fn stage(span: &[u8], ledger: &mut Ledger<'_>, scratch: &mut Scratch) -> StageStats {
    repeated_blocks(span, ledger, MIN_BLOCK_LINES, MAX_BLOCK_LINES, scratch)
}

fn record(len: usize, pad: &[u8]) -> Vec<u8> {
    filled_record(b'a', len, pad)
}

fn filled_record(fill: u8, len: usize, pad: &[u8]) -> Vec<u8> {
    let mut bytes = vec![b'{'];
    bytes.extend(std::iter::repeat_n(fill, len - 2 - pad.len()));
    bytes.extend_from_slice(pad);
    bytes.push(b'}');
    bytes
}

fn record_a(index: usize) -> Vec<u8> {
    filled_record(
        b'a',
        200,
        if index.is_multiple_of(2) {
            br"\t"
        } else {
            br"\r"
        },
    )
}

fn record_b(index: usize) -> Vec<u8> {
    filled_record(
        b'b',
        200,
        if index.is_multiple_of(2) {
            b"  "
        } else {
            br"\t"
        },
    )
}

fn unique_record(index: usize) -> Vec<u8> {
    filled_record(b'c', 200, format!("{index:06}").as_bytes())
}

fn filler(count: usize, start: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|index| unique_record(start + index))
        .collect()
}

fn copies(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .flat_map(|copy| [record_a(copy), record_b(copy)])
        .collect()
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

fn norm_block(span: &[u8], units: &[Unit], from: usize, len: usize) -> Vec<u8> {
    units[from..from + len]
        .iter()
        .flat_map(|unit| normalize(&span[unit.range.clone()]))
        .collect()
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
    let anchor_units = members
        .iter()
        .take_while(|unit| unit.range.end <= commit.anchor.end)
        .count();
    assert_eq!(commit.anchor.start, members[0].range.start);
    assert_eq!(
        commit.anchor.end,
        units[commit.first + anchor_units - 1].range.end
    );
    assert!(commit.anchor.end <= commit.removed.end);
    assert_eq!(members.len() % anchor_units, 0);
    assert_eq!(commit.count, (members.len() / anchor_units - 1) as u64);
    assert!(profitable(
        UNICODE,
        commit.kind,
        commit.count,
        commit.anchor.len(),
        commit.removed.len()
    ));
}

fn periodic_span(period: usize, lines: usize) -> Vec<u8> {
    let distinct: Vec<String> = (0..period)
        .map(|index| format!("trace line {index:04} payload padding 0123456789"))
        .collect();
    let mut span = Vec::new();
    for index in 0..lines {
        if index > 0 {
            span.extend_from_slice(br"\n");
        }
        span.extend_from_slice(distinct[index % period].as_bytes());
    }
    span
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
}

const PADS: [&str; 4] = ["\\t", "  ", " \\t ", "\\r\\t"];

fn generated_span(groups: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    let mut span = Vec::new();
    let push = |span: &mut Vec<u8>, line: &[u8]| {
        if !span.is_empty() {
            span.extend_from_slice(br"\n");
        }
        span.extend_from_slice(line);
    };
    for group in 0..groups {
        push(
            &mut span,
            format!("INFO run {group:04} unique {}", rng.next()).as_bytes(),
        );
        for pad in ["\\t", "  ", " \\t ", "\\t\\t"] {
            let mut first = b"INFO hc".to_vec();
            first.extend_from_slice(pad.as_bytes());
            first.extend_from_slice(br" 10.0.0.1 ok 0123456789 payload");
            push(&mut span, &first);
            let mut second = b"INFO hc".to_vec();
            second.extend_from_slice(PADS[(group + pad.len()) % PADS.len()].as_bytes());
            second.extend_from_slice(br" 10.0.0.2 ok 9876543210 payload");
            push(&mut span, &second);
        }
    }
    span
}

#[test]
fn a_block_behind_header_lines_commits() {
    let lines: [&[u8]; 8] = [H0, H1, L0, L1, L0P, L1P, L0Q, L1Q];
    let span = lines_span(&lines);
    let units = split_span(&span);
    assert_eq!(units.len(), 8);
    let mut exact = new_ledger(&units);
    assert_eq!(exact_runs(&span, &mut exact, 3), StageStats::default());
    let mut ws = new_ledger(&units);
    assert_eq!(
        ws_runs(&span, &mut ws, 3, &mut WsScratch::default()),
        StageStats::default()
    );
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    let stats = stage(&span, &mut ledger, &mut scratch);
    assert_eq!(stats.block_repeats, 1);
    assert_eq!(stats.groups_collapsed, 1);
    assert_eq!(stats.exact_runs, 0);
    assert_eq!(stats.ws_runs, 0);
    let commit = &ledger.commits()[0];
    assert_eq!(commit.kind, CommitKind::Block);
    assert_eq!((commit.first, commit.last, commit.count), (2, 7, 2));
    assert_eq!(commit.anchor, units[2].range.start..units[3].range.end);
    assert_eq!(&span[commit.anchor.clone()], lines_span(&[L0, L1]));
    assert_eq!(&span[commit.removed.clone()], lines_span(&lines[2..]));
    assert_eq!(
        ledger
            .residual()
            .map(|(index, _)| index)
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert_removal_invariant(&units, commit);
}

#[test]
fn the_leftmost_start_beats_a_longer_block_that_starts_later() {
    let lines: [&[u8]; 8] = [L0, L1, L0, L1, C0, L0, L1, C0];
    let span = lines_span(&lines);
    let units = split_span(&span);
    assert_eq!(
        norm_block(&span, &units, 2, 3),
        norm_block(&span, &units, 5, 3)
    );
    assert_ne!(
        norm_block(&span, &units, 0, 3),
        norm_block(&span, &units, 3, 3)
    );
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    assert_eq!(stage(&span, &mut ledger, &mut scratch).block_repeats, 1);
    let commit = &ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (0, 3, 1));
    assert_eq!(&span[commit.anchor.clone()], lines_span(&[L0, L1]));
    assert_removal_invariant(&units, commit);
    let tail: [&[u8]; 6] = [L0, L1, C0, L0, L1, C0];
    let tail_span = lines_span(&tail);
    let tail_units = split_span(&tail_span);
    let mut tail_ledger = new_ledger(&tail_units);
    assert_eq!(
        stage(&tail_span, &mut tail_ledger, &mut scratch).block_repeats,
        1
    );
    let commit = &tail_ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (0, 5, 1));
    assert_eq!(
        commit.anchor,
        tail_units[0].range.start..tail_units[2].range.end
    );
    assert_removal_invariant(&tail_units, commit);
}

#[test]
fn the_longest_candidate_at_a_start_wins() {
    let lines: [&[u8]; 8] = [L0, L1, L0, L1, L0, L1, L0, L1];
    let span = lines_span(&lines);
    let units = split_span(&span);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    assert_eq!(stage(&span, &mut ledger, &mut scratch).block_repeats, 1);
    let commit = &ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (0, 7, 1));
    assert_eq!(commit.anchor, units[0].range.start..units[3].range.end);
    assert_eq!(&span[commit.anchor.clone()], lines_span(&[L0, L1, L0, L1]));
    assert_eq!(marker_len(UNICODE, commit.kind, commit.count), 22);
    assert!(profitable(
        UNICODE,
        commit.kind,
        3,
        commit.anchor.len(),
        8 * 30 + 7 * 2
    ));
    assert_eq!(commit.removed.len(), 8 * 30 + 7 * 2);
    assert_removal_invariant(&units, commit);
}

#[test]
fn the_chain_stops_at_the_first_divergent_copy() {
    let lines: [&[u8]; 8] = [L0, L1, L0, L1, L0, L1, L0, LZ];
    let span = lines_span(&lines);
    let units = split_span(&span);
    assert_ne!(
        norm_block(&span, &units, 4, 2),
        norm_block(&span, &units, 6, 2)
    );
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    assert_eq!(stage(&span, &mut ledger, &mut scratch).block_repeats, 1);
    let commit = &ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (0, 5, 2));
    assert_eq!(&span[commit.anchor.clone()], lines_span(&[L0, L1]));
    assert_eq!(scratch.work().verifications, 2);
    assert!(!ledger.is_committed(6));
    assert!(!ledger.is_committed(7));
    assert_eq!(
        &span[units[6].range.start..units[7].range.end],
        lines_span(&[L0, LZ])
    );
    assert_removal_invariant(&units, commit);
}

#[test]
fn a_two_copy_block_costs_exactly_one_verification_memcmp() {
    let lines: [&[u8]; 4] = [L0, L1, L0, L1];
    let span = lines_span(&lines);
    let units = split_span(&span);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    assert_eq!(stage(&span, &mut ledger, &mut scratch).block_repeats, 1);
    let commit = &ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (0, 3, 1));
    assert_eq!(scratch.work().verifications, 1);
    assert_eq!(scratch.work().compares, 2);
    assert_eq!(&span[commit.anchor.clone()], lines_span(&[L0, L1]));
    assert_eq!(commit.removed.len(), 4 * 30 + 3 * 2);
    assert_removal_invariant(&units, commit);
}

#[test]
fn a_below_threshold_block_stays_verbatim_and_remains_free() {
    let narrow: [&[u8]; 4] = [br"a\tb", br"c d", br"a  b", br"c\td"];
    let span = lines_span(&narrow);
    let units = split_span(&span);
    assert_eq!(units.len(), 4);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    assert_eq!(
        stage(&span, &mut ledger, &mut scratch),
        StageStats::default()
    );
    assert!(!profitable(UNICODE, CommitKind::Block, 1, 10, 22));
    assert!(ledger.is_free(0..4));
    assert_eq!(
        ledger
            .residual()
            .map(|(index, _)| index)
            .collect::<Vec<_>>(),
        [0, 1, 2, 3]
    );
    assert_eq!(scratch.work().verifications, 1);
    assert_eq!(apply(&span, &ledger), span);
    assert_eq!(
        stage(&span, &mut ledger, &mut scratch),
        StageStats::default()
    );
    let wide: [&[u8]; 4] = [L0, L1, L0, L1];
    let wide_span = lines_span(&wide);
    let wide_units = split_span(&wide_span);
    let mut wide_ledger = new_ledger(&wide_units);
    assert_eq!(
        stage(&wide_span, &mut wide_ledger, &mut scratch).block_repeats,
        1
    );
}

#[test]
fn the_gate_boundary_is_the_emitted_count() {
    let alternating = |units: usize| -> Vec<u8> {
        let lines: Vec<&[u8]> = (0..units)
            .map(|index| if index % 2 == 0 { &b"a"[..] } else { &b"b"[..] })
            .collect();
        lines_span(&lines)
    };
    for (units, expected) in [(8usize, 0u64), (10, 1)] {
        let span = alternating(units);
        let parsed = split_span(&span);
        assert_eq!(parsed.len(), units);
        let mut ledger = new_ledger(&parsed);
        let mut scratch = Scratch::default();
        let stats = repeated_blocks(
            &span,
            &mut ledger,
            MIN_BLOCK_LINES,
            MIN_BLOCK_LINES,
            &mut scratch,
        );
        assert_eq!(stats.block_repeats, expected, "{units} units");
        let count = (units / 2 - 1) as u64;
        let removed = units + (units - 1) * 2;
        assert_eq!(
            profitable(UNICODE, CommitKind::Block, count, 4, removed),
            expected == 1,
            "{units} units"
        );
        if expected == 1 {
            let commit = &ledger.commits()[0];
            assert_eq!(commit.count, count);
            assert_eq!(commit.anchor, parsed[0].range.start..parsed[1].range.end);
            assert_eq!(commit.removed.len(), removed);
            assert_removal_invariant(&parsed, commit);
        }
    }
    assert!(!profitable(UNICODE, CommitKind::Block, 3, 4, 22));
    assert!(profitable(UNICODE, CommitKind::Block, 4, 4, 28));
}

#[test]
fn min_and_max_block_lines_bound_the_candidate_lengths() {
    let lines: [&[u8]; 5] = [H0, L0, L1, L0P, L1P];
    let span = lines_span(&lines);
    let units = split_span(&span);
    let mut scratch = Scratch::default();
    let mut ledger = new_ledger(&units);
    assert_eq!(
        repeated_blocks(&span, &mut ledger, 3, MAX_BLOCK_LINES, &mut scratch),
        StageStats::default()
    );
    let mut ledger = new_ledger(&units);
    assert_eq!(
        repeated_blocks(&span, &mut ledger, 9, MAX_BLOCK_LINES, &mut scratch),
        StageStats::default()
    );
    let mut ledger = new_ledger(&units);
    assert_eq!(
        repeated_blocks(
            &span,
            &mut ledger,
            MIN_BLOCK_LINES,
            MAX_BLOCK_LINES,
            &mut scratch
        )
        .block_repeats,
        1
    );
    let long: Vec<Vec<u8>> = (0..3)
        .flat_map(|_| {
            (0..70)
                .map(|line| format!("INFO hc step {line:02} payload 0123456789abcdef").into_bytes())
        })
        .collect();
    let borrowed: Vec<&[u8]> = long.iter().map(|line| line.as_slice()).collect();
    let wide = lines_span(&borrowed);
    let wide_units = split_span(&wide);
    assert_eq!(wide_units.len(), 210);
    let mut ledger = new_ledger(&wide_units);
    assert_eq!(
        repeated_blocks(
            &wide,
            &mut ledger,
            MIN_BLOCK_LINES,
            MAX_BLOCK_LINES,
            &mut scratch
        ),
        StageStats::default()
    );
    assert_eq!(ledger.commits().len(), 0);
    let mut ledger = new_ledger(&wide_units);
    let stats = repeated_blocks(&wide, &mut ledger, MIN_BLOCK_LINES, 128, &mut scratch);
    assert_eq!(stats.block_repeats, 1);
    let commit = &ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (0, 209, 2));
    assert_eq!(
        commit.anchor,
        wide_units[0].range.start..wide_units[69].range.end
    );
    assert_removal_invariant(&wide_units, commit);
}

#[test]
fn the_anchor_is_the_entire_raw_first_occurrence() {
    let lines: [&[u8]; 4] = [L0, L1, L0P, L1P];
    let span = lines_span(&lines);
    let units = split_span(&span);
    assert_ne!(&span[units[0].range.clone()], &span[units[2].range.clone()]);
    assert_eq!(
        norm_block(&span, &units, 0, 2),
        norm_block(&span, &units, 2, 2)
    );
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    assert_eq!(stage(&span, &mut ledger, &mut scratch).block_repeats, 1);
    let commit = &ledger.commits()[0];
    let anchor = &span[commit.anchor.clone()];
    assert_eq!(anchor, lines_span(&[L0, L1]));
    assert_eq!(anchor.len(), L0.len() + 2 + L1.len());
    assert_ne!(anchor, &norm_block(&span, &units, 0, 2)[..]);
    assert_eq!(commit.count, 1);
    assert_eq!(render(UNICODE, commit.kind, 1, anchor).len(), 22);
    let mut expected = lines_span(&lines[..2]);
    expected.extend_from_slice(&render(UNICODE, commit.kind, 1, anchor));
    assert_eq!(apply(&span, &ledger), expected);
    assert_removal_invariant(&units, commit);
}

#[test]
fn a_repeated_record_block_in_a_single_line_dump_commits() {
    let mut records = filler(200, 0);
    records.extend(copies(3));
    records.extend(filler(400, 1000));
    let span = dump(&records);
    assert!(span.len() > MAX_LINE_BYTES);
    let units = split_span(&span);
    assert_eq!(units.len(), 606);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    assert_eq!(stage(&span, &mut ledger, &mut scratch).block_repeats, 1);
    let commit = &ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (200, 205, 2));
    assert_eq!(commit.anchor, units[200].range.start..units[201].range.end);
    assert_eq!(commit.removed.len(), 6 * 200 + 5);
    assert_eq!(
        norm_block(&span, &units, 200, 2),
        norm_block(&span, &units, 202, 2)
    );
    assert_eq!(
        norm_block(&span, &units, 202, 2),
        norm_block(&span, &units, 204, 2)
    );
    assert!(!ledger.is_committed(199));
    assert!(!ledger.is_committed(206));
    assert_removal_invariant(&units, commit);
}

#[test]
fn a_block_never_folds_an_over_cap_record() {
    let mut records = filler(200, 0);
    records.extend(copies(2));
    records.push(record(MAX_RECORD_BYTES + 1, br"\t"));
    records.extend(copies(2));
    records.extend(filler(400, 1000));
    let span = dump(&records);
    assert!(span.len() > MAX_LINE_BYTES);
    let units = split_span(&span);
    assert_eq!(units.len(), 609);
    let wall = 204;
    assert!(!units[wall].eligible);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    assert_eq!(stage(&span, &mut ledger, &mut scratch).block_repeats, 2);
    assert_eq!(
        ledger
            .commits()
            .iter()
            .map(|commit| (commit.first, commit.last, commit.count))
            .collect::<Vec<_>>(),
        [(200, 203, 1), (205, 208, 1)]
    );
    for commit in ledger.commits() {
        assert!(commit.last < wall || commit.first > wall);
        assert_removal_invariant(&units, commit);
    }
    assert!(!ledger.is_committed(wall));
    assert!(ledger.is_free(wall..wall + 1));
    records.remove(wall);
    let whole = dump(&records);
    let whole_units = split_span(&whole);
    assert_eq!(whole_units.len(), 608);
    let mut whole_ledger = new_ledger(&whole_units);
    assert_eq!(
        stage(&whole, &mut whole_ledger, &mut scratch).block_repeats,
        1
    );
    let commit = &whole_ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (200, 207, 1));
    assert_eq!(
        commit.anchor,
        whole_units[200].range.start..whole_units[203].range.end
    );
    assert_removal_invariant(&whole_units, commit);
}

#[test]
fn a_block_never_straddles_a_committed_region() {
    let lines: [&[u8]; 6] = [L0, L1, L0, L1, L0, L1];
    let span = lines_span(&lines);
    let units = split_span(&span);
    let mut ledger = new_ledger(&units);
    assert!(matches!(
        ledger.try_commit(Proposal::run(2..4, CommitKind::ExactRun)),
        CommitOutcome::Committed(_)
    ));
    let mut scratch = Scratch::default();
    assert_eq!(
        stage(&span, &mut ledger, &mut scratch),
        StageStats::default()
    );
    assert_eq!(ledger.commits().len(), 1);
    assert_eq!(
        ledger
            .residual()
            .map(|(index, _)| index)
            .collect::<Vec<_>>(),
        [0, 1, 4, 5]
    );
    let long: [&[u8]; 12] = [L0, L1, L0, L1, L0, L1, L0, L1, L0, L1, L0, L1];
    let span = lines_span(&long);
    let units = split_span(&span);
    let mut ledger = new_ledger(&units);
    assert!(matches!(
        ledger.try_commit(Proposal::run(2..4, CommitKind::ExactRun)),
        CommitOutcome::Committed(_)
    ));
    assert_eq!(stage(&span, &mut ledger, &mut scratch).block_repeats, 1);
    let commit = &ledger.commits()[1];
    assert_eq!((commit.first, commit.last, commit.count), (4, 11, 1));
    for commit in ledger.commits() {
        assert_removal_invariant(&units, commit);
    }
}

#[test]
fn stage_five_commits_only_what_stages_three_and_four_left() {
    let lines: [&[u8]; 7] = [E0, E0, E0, L0, L1, L0P, L1P];
    let span = lines_span(&lines);
    let units = split_span(&span);
    assert_eq!(units.len(), 7);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    let first = exact_runs(&span, &mut ledger, 3);
    assert_eq!(first.exact_runs, 1);
    let second = ws_runs(&span, &mut ledger, 3, &mut WsScratch::default());
    assert_eq!(second.ws_runs, 0);
    let third = stage(&span, &mut ledger, &mut scratch);
    assert_eq!(third.block_repeats, 1);
    assert_eq!(
        ledger
            .commits()
            .iter()
            .map(|commit| (commit.kind, commit.first, commit.last))
            .collect::<Vec<_>>(),
        [(CommitKind::ExactRun, 0, 2), (CommitKind::Block, 3, 6)]
    );
    assert_eq!(
        &span[ledger.commits()[1].anchor.clone()],
        lines_span(&[L0, L1])
    );
    for commit in ledger.commits() {
        assert_removal_invariant(&units, commit);
    }
}

#[test]
fn a_unique_line_flood_degrades_to_pass_through() {
    let mut lines: Vec<Vec<u8>> = vec![L0.to_vec(), L1.to_vec(), L0P.to_vec(), L1P.to_vec()];
    for index in 0..200_000u32 {
        lines.push(
            format!("2026-08-26T10:00:00Z INFO worker {index:06} ok payload 0123456789")
                .into_bytes(),
        );
    }
    let borrowed: Vec<&[u8]> = lines.iter().map(|line| line.as_slice()).collect();
    let span = lines_span(&borrowed);
    let units = split_span(&span);
    assert_eq!(units.len(), 200_004);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    assert_eq!(
        stage(&span, &mut ledger, &mut scratch),
        StageStats::default()
    );
    assert_eq!(ledger.commits().len(), 0);
    assert_eq!(ledger.residual().count(), units.len());
    assert_eq!(apply(&span, &ledger), span);
    assert_eq!(scratch.work().verifications, 0);
    assert!(scratch.degraded());
    let control: [&[u8]; 8] = [H0, H1, L0, L1, L0P, L1P, L0Q, L1Q];
    let control_span = lines_span(&control);
    let control_units = split_span(&control_span);
    let mut control_ledger = new_ledger(&control_units);
    assert_eq!(
        stage(&control_span, &mut control_ledger, &mut scratch).block_repeats,
        1
    );
    assert!(!scratch.degraded());
}

#[test]
fn a_periodic_payload_stays_within_the_capped_work_bound() {
    let period = MAX_BLOCK_LINES as usize * 2 + 1;
    let lines = 40_000;
    let span = periodic_span(period, lines);
    let units = split_span(&span);
    assert_eq!(units.len(), lines);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    assert_eq!(
        stage(&span, &mut ledger, &mut scratch),
        StageStats::default()
    );
    assert_eq!(scratch.work().verifications, 0);
    assert!(scratch.work().compares > lines as u64);
    let work = scratch.work();
    assert!(
        work.compares <= (MAX_BLOCK_LINES as u64 - 1) * lines as u64,
        "{} compares",
        work.compares
    );
    assert!(work.scanned <= lines as u64, "{} scanned", work.scanned);
    assert!(
        work.compares + work.scanned <= (MAX_BLOCK_LINES as u64 + 1) * lines as u64,
        "{} steps",
        work.compares + work.scanned
    );
    let short = periodic_span(period, lines / 2);
    let short_units = split_span(&short);
    let mut short_ledger = new_ledger(&short_units);
    let mut short_scratch = Scratch::default();
    assert_eq!(
        stage(&short, &mut short_ledger, &mut short_scratch),
        StageStats::default()
    );
    let half = short_scratch.work();
    let slack = 2 * MAX_BLOCK_LINES as u64 * MAX_BLOCK_LINES as u64;
    assert!(
        (work.compares + work.scanned) <= 2 * (half.compares + half.scanned) + slack,
        "{} steps for twice the units",
        work.compares + work.scanned
    );
    let mut tail_span = lines_span(&[L0, L1, L0P, L1P]);
    tail_span.extend_from_slice(br"\n");
    tail_span.extend_from_slice(&periodic_span(period, 2000));
    let tail_units = split_span(&tail_span);
    assert_eq!(tail_units.len(), 2004);
    let mut tail_ledger = new_ledger(&tail_units);
    let mut tail_scratch = Scratch::default();
    assert_eq!(
        stage(&tail_span, &mut tail_ledger, &mut tail_scratch).block_repeats,
        1
    );
    let commit = &tail_ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (0, 3, 1));
    assert_eq!(tail_scratch.work().verifications, 1);
    assert!(tail_scratch.work().compares > 60 * 1000);
    assert_removal_invariant(&tail_units, commit);
}

#[test]
fn repeated_blocks_is_deterministic() {
    let span = generated_span(60, 0x5eed_1234_abcd_0303);
    let units = split_span(&span);
    let mut first = new_ledger(&units);
    let mut second = new_ledger(&units);
    let mut scratch = Scratch::default();
    let mut other = Scratch::with_capacity(span.len(), 64);
    let stats = stage(&span, &mut first, &mut scratch);
    assert_eq!(stage(&span, &mut second, &mut other), stats);
    assert!(
        stats.block_repeats > 10,
        "the generator produced too few blocks"
    );
    assert_eq!(first.commits(), second.commits());
    assert_eq!(apply(&span, &first), apply(&span, &second));
    assert_eq!(
        stage(&span, &mut first, &mut scratch),
        StageStats::default()
    );
    assert_eq!(first.commits(), second.commits());
    for commit in first.commits() {
        assert_removal_invariant(&units, commit);
    }
    let other_span = generated_span(60, 0x0f0f_0f0f_0f0f_0f0f);
    let other_units = split_span(&other_span);
    let mut third = new_ledger(&other_units);
    let mut fourth = new_ledger(&other_units);
    assert_eq!(
        stage(&other_span, &mut third, &mut scratch),
        stage(&other_span, &mut fourth, &mut other)
    );
    assert_eq!(apply(&other_span, &third), apply(&other_span, &fourth));
}

#[test]
fn the_scratch_holds_each_residual_unit_once() {
    let span = generated_span(50, 0x1234_5678_9abc_def0);
    let units = split_span(&span);
    let widest = units.iter().map(|unit| unit.range.len()).max().unwrap();
    let normalized: usize = units
        .iter()
        .map(|unit| normalize(&span[unit.range.clone()]).len())
        .sum();
    let mut scratch = Scratch::with_capacity(span.len(), widest);
    let mut ledger = new_ledger(&units);
    let stats = stage(&span, &mut ledger, &mut scratch);
    assert!(stats.block_repeats > 5);
    let (arena, line) = scratch.reserved();
    assert!(arena >= normalized);
    assert_eq!(line, widest);
    assert!(arena <= 2 * span.len());
    let small: [&[u8]; 4] = [L0, L1, L0, L1];
    let small_span = lines_span(&small);
    let small_units = split_span(&small_span);
    let mut small_ledger = new_ledger(&small_units);
    assert_eq!(
        stage(&small_span, &mut small_ledger, &mut scratch).block_repeats,
        1
    );
    assert_eq!(scratch.reserved(), (arena, line));
    let mut grown = Scratch::default();
    let mut grown_ledger = new_ledger(&units);
    assert_eq!(stage(&span, &mut grown_ledger, &mut grown), stats);
    assert!(grown.reserved().1 <= 2 * widest);
    assert!(grown.reserved().0 <= 2 * span.len());
}

#[test]
fn empty_narrow_and_wall_spans_commit_nothing() {
    let mut scratch = Scratch::default();
    let empty: &[u8] = b"";
    let units = split_span(empty);
    let mut ledger = new_ledger(&units);
    assert_eq!(
        stage(empty, &mut ledger, &mut scratch),
        StageStats::default()
    );
    let single: &[u8] = br"only one line here";
    let units = split_span(single);
    let mut ledger = new_ledger(&units);
    assert_eq!(
        stage(single, &mut ledger, &mut scratch),
        StageStats::default()
    );
    let pair: [&[u8]; 2] = [L0, L0];
    let span = lines_span(&pair);
    let units = split_span(&span);
    let mut ledger = new_ledger(&units);
    assert_eq!(
        stage(&span, &mut ledger, &mut scratch),
        StageStats::default()
    );
    let wall = vec![b'z'; MAX_LINE_BYTES + 1];
    let units = split_span(&wall);
    assert_eq!(units.len(), 1);
    assert!(!units[0].eligible);
    let mut ledger = new_ledger(&units);
    assert_eq!(
        stage(&wall, &mut ledger, &mut scratch),
        StageStats::default()
    );
    assert!(ledger.is_free(0..1));
}

#[test]
fn the_blocks_module_has_no_forbidden_determinism_inputs() {
    let source = include_str!("../src/detect/blocks.rs");
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
        assert!(!source.contains(banned), "blocks must not use {banned}");
    }
    assert!(source.contains("normalize_into"));
    assert!(source.contains("FingerprintTable"));
    assert!(source.contains("Proposal::repeat"));
    assert!(source.contains("CommitKind::Block"));
}
