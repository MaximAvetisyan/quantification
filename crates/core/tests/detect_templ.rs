use quantification_core::config::{MAX_LINE_BYTES, MAX_RECORD_BYTES, MarkerStyle};
use quantification_core::detect::exact::exact_runs;
use quantification_core::detect::templ::{Forms, Scratch, TemplateId, template_groups};
use quantification_core::detect::wsruns::{Scratch as WsScratch, ws_runs};
use quantification_core::fingerprint::{MAX_SLOTS, fingerprint};
use quantification_core::ledger::{
    Commit, CommitKind, CommitOutcome, Ledger, Proposal, StageStats, marker_len, profitable,
};
use quantification_core::mask::mask;
use quantification_core::render::render;
use quantification_core::stage1::{Unit, split_span};
use quantification_core::wsnorm::normalize;

const UNICODE: MarkerStyle = MarkerStyle::Unicode;
const TEMPLATE_MARKER: &[u8] = "\u{27ea}\u{d7}2 rows, template \u{b7}7837\u{27eb}".as_bytes();
const MASKED_INFO: &[u8] = b"<ts> INFO svc <ip> id=<uuid> took <dur>";
const MASKED_ERROR: &[u8] = b"<ts> ERROR svc <ip> id=<uuid> took <dur>";
const MASKED_DEBUG: &[u8] = b"<ts> DEBUG svc <ip> id=<uuid> took <dur>";

const L0: &[u8] =
    br"2026-08-26T10:00:00Z INFO svc 10.0.0.1 id=123e4567-e89b-12d3-a456-426614174000 took 12ms";
const L1: &[u8] =
    br"2026-08-26T10:00:07Z INFO svc 10.0.0.2 id=9f8e7d6c-5b4a-4938-8271-6a5b4c3d2e1f took 19ms";
const L2: &[u8] =
    br"2026-08-26T10:00:42Z INFO svc 192.168.4.9 id=0f1e2d3c-4b5a-4968-8776-655443332211 took 7ms";
const L3: &[u8] =
    br"2026-08-26T10:01:00Z INFO svc 10.0.0.4 id=aabbccdd-1122-4334-8556-66778899aabb took 44ms";
const L4: &[u8] =
    br"2026-08-26T10:01:31Z INFO svc fe80::1 id=deadbeef-cafe-4bab-8ede-fedcba987654 took 9ms";
const L5: &[u8] =
    br"2026-08-26T10:02:02Z INFO svc 10.0.0.5 id=00112233-4455-4677-8899-aabbccddeeff took 31ms";
const ERROR_LINE: &[u8] =
    br"2026-08-26T10:00:55Z ERROR svc 10.0.0.3 id=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee took 3ms";
const DEBUG_LINE: &[u8] =
    br"2026-08-26T10:00:11Z DEBUG svc 10.0.0.7 id=77778888-9999-4aaa-8bbb-ccccdddddddd took 5ms";

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

fn id_of(line: &[u8]) -> TemplateId {
    TemplateId(fingerprint(&mask(&normalize(line))) as u64)
}

fn assert_masked_domain_forms(span: &[u8], units: &[Unit], forms: &Forms) {
    assert_eq!(forms.len(), units.len());
    for (index, unit) in units.iter().enumerate() {
        let raw = &span[unit.range.clone()];
        assert_eq!(
            forms.masked(index),
            &mask(&normalize(raw))[..],
            "unit {index}"
        );
    }
}

fn tag(mut n: usize) -> String {
    let mut out = String::new();
    for _ in 0..4 {
        out.push((b'a' + (n % 26) as u8) as char);
        n /= 26;
    }
    out
}

fn distinct_shape(index: usize) -> String {
    format!("{} row 7 42", tag(index))
}

fn repeated_lines(count: usize, line: &str) -> Vec<u8> {
    let mut span = Vec::with_capacity(count * (line.len() + 2));
    for index in 0..count {
        if index > 0 {
            span.extend_from_slice(br"\n");
        }
        span.extend_from_slice(line.as_bytes());
    }
    span
}

const LEVELS: [&str; 4] = ["INFO", "WARN", "ERROR", "DEBUG"];

fn generated_span(lines: usize) -> Vec<u8> {
    let mut span = Vec::new();
    for index in 0..lines {
        if index > 0 {
            span.extend_from_slice(br"\n");
        }
        let level = LEVELS[index / 3 % LEVELS.len()];
        span.extend_from_slice(
            format!(
                r"2026-08-26T10:{:02}:{:02}Z {level} svc 10.0.{}.{} id=123e4567-e89b-12d3-a456-{:012} took {}ms seq={index}",
                index / 60 % 60,
                index % 60,
                index / 256 % 256,
                index % 256,
                index,
                1 + index % 900,
            )
            .as_bytes(),
        );
    }
    span
}

#[test]
fn a_log_burst_collapses_to_one_representative_and_a_marker() {
    let span = span_with(br"\n", &[L0, L1, L2]);
    let units = split_span(&span);
    assert_eq!(units.len(), 3);
    let mut exact = new_ledger(&units);
    let mut ws = new_ledger(&units);
    let mut ws_scratch = WsScratch::default();
    assert_eq!(exact_runs(&span, &mut exact, 3), StageStats::default());
    assert_eq!(
        ws_runs(&span, &mut ws, 3, &mut ws_scratch),
        StageStats::default()
    );
    assert_eq!(exact.commits().len(), 0);
    assert_eq!(ws.commits().len(), 0);

    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    let out = template_groups(&span, &mut ledger, 3, &mut scratch);
    assert!(!out.degraded);
    assert_eq!(out.stats.template_groups, 1);
    assert_eq!(out.stats.groups_collapsed, 1);
    assert_eq!(out.stats.exact_runs, 0);
    assert_eq!(out.stats.ws_runs, 0);
    assert_eq!(out.stats.block_repeats, 0);
    assert_eq!(out.stats.templated_blocks, 0);
    assert_eq!(out.stats.record_splits, 0);
    assert_eq!(ledger.commits().len(), 1);
    let commit = &ledger.commits()[0];
    assert_eq!(commit.kind, CommitKind::TemplateGroup);
    assert_eq!((commit.first, commit.last, commit.count), (0, 2, 2));
    assert_eq!(commit.anchor, units[0].range.clone());
    assert_eq!(commit.removed.len(), L0.len() + L1.len() + L2.len() + 4);
    assert_eq!(marker_len(UNICODE, commit.kind, commit.count), 31);
    assert_removal_invariant(&units, commit);
    assert_eq!(render(UNICODE, commit.kind, 2, L0), TEMPLATE_MARKER);
    assert_eq!(apply(&span, &ledger), [L0, TEMPLATE_MARKER].concat());
    assert_eq!(ledger.residual().count(), 0);
}

#[test]
fn the_anchor_is_the_raw_original_bytes_never_the_masked_form() {
    let span = span_with(br"\n", &[L0, L1, L2]);
    let units = split_span(&span);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    let out = template_groups(&span, &mut ledger, 3, &mut scratch);
    let anchor = &span[ledger.commits()[0].anchor.clone()];
    assert_eq!(anchor, L0);
    assert!(anchor.starts_with(b"2026-08-26T10:00:00Z"));
    assert!(anchor.windows(9).any(|w| w == b"10.0.0.1 "));
    assert!(anchor.ends_with(b"123e4567-e89b-12d3-a456-426614174000 took 12ms"));
    assert_ne!(anchor, MASKED_INFO);
    assert_ne!(anchor, out.forms.masked(0));
    assert_ne!(normalize(anchor), out.forms.masked(1));
    assert_eq!(out.forms.masked(0), MASKED_INFO);
    assert_eq!(out.forms.masked(1), MASKED_INFO);
    assert_eq!(out.forms.masked(2), MASKED_INFO);
    assert_eq!(apply(&span, &ledger), [L0, TEMPLATE_MARKER].concat());
}

#[test]
fn a_group_below_min_group_size_stays_verbatim_and_still_gets_template_ids() {
    let span = span_with(br"\n", &[L0, L1]);
    let units = split_span(&span);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    let out = template_groups(&span, &mut ledger, 3, &mut scratch);
    assert_eq!(out.stats, StageStats::default());
    assert!(!out.degraded);
    assert_eq!(ledger.commits().len(), 0);
    assert!(ledger.is_free(0..2));
    assert_eq!(
        ledger
            .residual()
            .map(|(index, _)| index)
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert_eq!(apply(&span, &ledger), span);
    assert_eq!(out.forms.len(), 2);
    assert_eq!(out.forms.id(0), out.forms.id(1));
    assert_eq!(out.forms.id(0), id_of(L0));
    assert_eq!(out.forms.id(1), id_of(L1));
    assert!(out.forms.same(0, 1));
    assert_masked_domain_forms(&span, &units, &out.forms);
    let again = template_groups(&span, &mut ledger, 3, &mut scratch);
    assert_eq!(again.stats, StageStats::default());
    assert_eq!(again.forms, out.forms);
}

#[test]
fn min_group_size_bounds_the_smallest_template_group() {
    let pair = span_with(br"\n", &[L0, L1]);
    let units = split_span(&pair);
    for min in [3, 4, 9] {
        let mut ledger = new_ledger(&units);
        let mut scratch = Scratch::default();
        assert_eq!(
            template_groups(&pair, &mut ledger, min, &mut scratch).stats,
            StageStats::default(),
            "min {min}"
        );
        assert_eq!(ledger.commits().len(), 0, "min {min}");
    }
    for min in [0, 1, 2] {
        let mut ledger = new_ledger(&units);
        let mut scratch = Scratch::default();
        assert_eq!(
            template_groups(&pair, &mut ledger, min, &mut scratch)
                .stats
                .template_groups,
            1,
            "min {min}"
        );
        let commit = &ledger.commits()[0];
        assert_eq!((commit.first, commit.last, commit.count), (0, 1, 1));
        assert_removal_invariant(&units, commit);
    }
}

#[test]
fn a_group_the_profitability_gate_rejects_stays_verbatim_and_keeps_its_ids() {
    let narrow: [&[u8]; 3] = [b"a 1", b"a 2", b"a 3"];
    let span = span_with(br"\n", &narrow);
    let units = split_span(&span);
    assert_eq!(mask(&normalize(narrow[0])), b"a <num>");
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    let out = template_groups(&span, &mut ledger, 3, &mut scratch);
    assert_eq!(out.stats, StageStats::default());
    assert!(!profitable(UNICODE, CommitKind::TemplateGroup, 2, 3, 13));
    assert!(ledger.is_free(0..3));
    assert_eq!(apply(&span, &ledger), span);
    assert_eq!(out.forms.len(), 3);
    assert_eq!(out.forms.id(0), out.forms.id(2));
    assert_ne!(out.forms.id(0), id_of(b"b 1"));
    assert_masked_domain_forms(&span, &units, &out.forms);
}

#[test]
fn leftmost_first_commit_order_with_an_intervening_line() {
    let span = span_with(br"\n", &[L0, L1, L2, ERROR_LINE, L3, L4, L5]);
    let units = split_span(&span);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    let out = template_groups(&span, &mut ledger, 3, &mut scratch);
    assert_eq!(out.stats.template_groups, 2);
    assert_eq!(ledger.commits().len(), 2);
    assert_eq!(
        ledger
            .commits()
            .iter()
            .map(|commit| (commit.kind, commit.first, commit.last, commit.count))
            .collect::<Vec<_>>(),
        [
            (CommitKind::TemplateGroup, 0, 2, 2),
            (CommitKind::TemplateGroup, 4, 6, 2)
        ]
    );
    assert!(ledger.commits()[0].anchor.start < ledger.commits()[1].anchor.start);
    assert!(!ledger.is_committed(3));
    assert_eq!(&span[ledger.commits()[1].anchor.clone()], L3);
    assert_eq!(out.forms.id(0), out.forms.id(6));
    assert_ne!(out.forms.id(0), out.forms.id(3));
    assert_eq!(out.forms.masked(3), MASKED_ERROR);
    assert_eq!(
        ledger
            .residual()
            .map(|(index, _)| index)
            .collect::<Vec<_>>(),
        [3]
    );
    for commit in ledger.commits() {
        assert_removal_invariant(&units, commit);
    }
    let spliced = apply(&span, &ledger);
    assert_eq!(
        spliced,
        [
            L0,
            TEMPLATE_MARKER,
            br"\n",
            ERROR_LINE,
            br"\n",
            L3,
            &render(UNICODE, CommitKind::TemplateGroup, 2, L3),
        ]
        .concat()
    );
    assert_eq!(
        render(UNICODE, CommitKind::TemplateGroup, 2, L3),
        "\u{27ea}\u{d7}2 rows, template \u{b7}b3f1\u{27eb}".as_bytes()
    );
}

#[test]
fn a_template_group_never_straddles_a_committed_region() {
    let span = span_with(br"\n", &[L0, L2, L2, L1, L2, L3]);
    let units = split_span(&span);
    assert_eq!(units.len(), 6);
    assert_eq!(mask(&normalize(&span[units[5].range.clone()])), MASKED_INFO);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    assert_eq!(exact_runs(&span, &mut ledger, 2).exact_runs, 1);
    let out = template_groups(&span, &mut ledger, 3, &mut scratch);
    assert_eq!(out.stats.template_groups, 1);
    assert_eq!(
        ledger
            .commits()
            .iter()
            .map(|commit| (commit.kind, commit.first, commit.last))
            .collect::<Vec<_>>(),
        [
            (CommitKind::ExactRun, 1, 2),
            (CommitKind::TemplateGroup, 3, 5)
        ]
    );
    assert!(!ledger.is_committed(0));
    assert!(ledger.is_free(0..1));
    assert_eq!(
        ledger
            .residual()
            .map(|(index, _)| index)
            .collect::<Vec<_>>(),
        [0]
    );
    assert_eq!(out.forms.len(), 6);
    assert_eq!(out.forms.id(0), out.forms.id(5));
    assert_eq!(out.forms.id(0), id_of(L0));
    assert_masked_domain_forms(&span, &units, &out.forms);
}

#[test]
fn an_over_cap_record_wall_splits_template_groups() {
    let records: Vec<Vec<u8>> = (0..200)
        .map(|i| {
            format!(
                r#"{{"seq":{i},"ts":"2026-08-26T10:00:00Z","ip":"10.0.0.{i}","took":"{i}ms","pad":"{}"}}"#,
                "a".repeat(130)
            )
            .into_bytes()
        })
        .collect();
    assert!(records[0].len() <= MAX_RECORD_BYTES);
    let wall = format!(r#"{{"seq":0,"blob":"{}"}}"#, "z".repeat(MAX_RECORD_BYTES));
    assert!(wall.len() > MAX_RECORD_BYTES);
    let mut all = records.clone();
    all.push(wall.into_bytes());
    all.extend(records);
    let mut span = vec![b'['];
    for (index, record) in all.iter().enumerate() {
        if index > 0 {
            span.push(b',');
        }
        span.extend_from_slice(record);
    }
    span.push(b']');
    assert!(span.len() > MAX_LINE_BYTES);
    let units = split_span(&span);
    assert_eq!(units.len(), 401);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    let out = template_groups(&span, &mut ledger, 3, &mut scratch);
    assert_eq!(out.stats.template_groups, 2);
    assert_eq!(
        ledger
            .commits()
            .iter()
            .map(|commit| (commit.first, commit.last, commit.count))
            .collect::<Vec<_>>(),
        [(1, 199, 198), (201, 399, 198)]
    );
    assert!(!units[200].eligible);
    assert!(ledger.is_free(200..201));
    assert_eq!(
        ledger
            .residual()
            .map(|(index, _)| index)
            .collect::<Vec<_>>(),
        [0, 200, 400]
    );
    assert_eq!(out.forms.len(), 401);
    assert_eq!(out.forms.id(1), out.forms.id(399));
    assert_ne!(out.forms.id(0), out.forms.id(1));
    assert_ne!(out.forms.id(200), out.forms.id(1));
    assert_masked_domain_forms(&span, &units, &out.forms);
    for commit in ledger.commits() {
        assert_removal_invariant(&units, commit);
        assert!(commit.first > 200 || commit.last < 200);
    }
}

#[test]
fn every_unit_gets_a_masked_form_and_a_template_id() {
    let span = span_with(
        br"\n",
        &[L0, L1, L2, DEBUG_LINE, DEBUG_LINE, DEBUG_LINE, ERROR_LINE],
    );
    let units = split_span(&span);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    assert_eq!(exact_runs(&span, &mut ledger, 3).exact_runs, 1);
    let out = template_groups(&span, &mut ledger, 3, &mut scratch);
    assert_eq!(out.stats.template_groups, 1);
    assert_eq!(ledger.commits().len(), 2);
    assert_eq!(
        ledger
            .commits()
            .iter()
            .map(|commit| (commit.kind, commit.first, commit.last))
            .collect::<Vec<_>>(),
        [
            (CommitKind::TemplateGroup, 0, 2),
            (CommitKind::ExactRun, 3, 5)
        ]
    );
    assert!(ledger.is_committed(3));
    assert!(ledger.is_committed(5));
    assert_eq!(out.forms.len(), 7);
    assert_masked_domain_forms(&span, &units, &out.forms);
    assert_eq!(out.forms.masked(4), MASKED_DEBUG);
    assert_eq!(out.forms.masked(3), MASKED_DEBUG);
    assert_ne!(out.forms.id(0), out.forms.id(3));
    assert_eq!(out.forms.id(0), out.forms.id(2));
    assert_eq!(out.forms.id(3), id_of(DEBUG_LINE));
    assert_eq!(out.forms.id(6), id_of(ERROR_LINE));
    for left in 0..units.len() {
        for right in 0..units.len() {
            if out.forms.id(left) == out.forms.id(right) {
                assert_eq!(
                    out.forms.masked(left),
                    out.forms.masked(right),
                    "{left}/{right}"
                );
            }
        }
    }
    assert_eq!(
        apply(&span, &ledger),
        [
            L0,
            TEMPLATE_MARKER,
            br"\n",
            DEBUG_LINE,
            &render(UNICODE, CommitKind::ExactRun, 2, DEBUG_LINE),
            br"\n",
            ERROR_LINE,
        ]
        .concat()
    );
}

#[test]
fn template_ids_are_content_derived_and_deterministic() {
    let lines: [&[u8]; 5] = [L0, L1, ERROR_LINE, L2, L3];
    let span = span_with(br"\n", &lines);
    let units = split_span(&span);
    let mut first = new_ledger(&units);
    let mut second = new_ledger(&units);
    let mut scratch = Scratch::default();
    let mut other = Scratch::with_capacity(0, 0);
    let left = template_groups(&span, &mut first, 3, &mut scratch);
    let right = template_groups(&span, &mut second, 3, &mut other);
    assert_eq!(left.forms, right.forms);
    assert_eq!(left.stats, right.stats);
    assert_eq!(first.commits(), second.commits());
    for (index, line) in lines.iter().enumerate() {
        assert_eq!(left.forms.id(index), id_of(line), "unit {index}");
    }

    let order = [4usize, 2, 0, 3, 1];
    let permuted: Vec<&[u8]> = order.iter().map(|index| lines[*index]).collect();
    let shuffled = span_with(br"\n", &permuted);
    let shuffled_units = split_span(&shuffled);
    let mut ledger = new_ledger(&shuffled_units);
    let other_forms = template_groups(&shuffled, &mut ledger, 3, &mut other).forms;
    assert_eq!(other_forms.len(), left.forms.len());
    for (slot, source) in order.iter().enumerate() {
        assert_eq!(other_forms.id(slot), left.forms.id(*source), "slot {slot}");
        assert_eq!(
            other_forms.masked(slot),
            left.forms.masked(*source),
            "slot {slot}"
        );
    }
    let mut ids: Vec<u64> = (0..left.forms.len()).map(|i| left.forms.id(i).0).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 2, "the span carries two distinct templates");
}

#[test]
fn a_span_of_all_distinct_templates_is_a_no_op() {
    let count = 64;
    let lines: Vec<String> = (0..count).map(distinct_shape).collect();
    let borrowed: Vec<&[u8]> = lines.iter().map(|line| line.as_bytes()).collect();
    let span = span_with(br"\n", &borrowed);
    let units = split_span(&span);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    let out = template_groups(&span, &mut ledger, 3, &mut scratch);
    assert!(!out.degraded);
    assert_eq!(out.stats, StageStats::default());
    assert_eq!(ledger.commits().len(), 0);
    assert_eq!(apply(&span, &ledger), span);
    assert_eq!(ledger.residual().count(), count);
    assert_eq!(out.forms.len(), count);
    for (index, line) in lines.iter().enumerate() {
        assert_eq!(out.forms.id(index), id_of(line.as_bytes()), "unit {index}");
    }
    let ids: Vec<TemplateId> = (0..count).map(|index| out.forms.id(index)).collect();
    for left in 0..count {
        assert!(!ids[..left].contains(&ids[left]), "unit {left} collided");
        assert!(!out.forms.same(left, (left + 1) % count), "unit {left}");
    }
}

#[test]
fn a_full_fingerprint_table_degrades_the_span_to_pass_through() {
    let count = 200_000;
    let mut span = Vec::with_capacity(count * 15);
    for index in 0..count {
        if index > 0 {
            span.extend_from_slice(br"\n");
        }
        span.extend_from_slice(distinct_shape(index).as_bytes());
    }
    assert!(span.len() >= MAX_SLOTS * 8 && span.len() < MAX_SLOTS * 16);
    let units = split_span(&span);
    assert_eq!(units.len(), count);
    let mut ledger = new_ledger(&units);
    let mut scratch = Scratch::default();
    let out = template_groups(&span, &mut ledger, 3, &mut scratch);
    assert!(out.degraded);
    assert_eq!(out.stats, StageStats::default());
    assert_eq!(out.forms, Forms::default());
    assert!(out.forms.is_empty());
    assert_eq!(ledger.commits().len(), 0);
    assert_eq!(ledger.residual().count(), count);
    assert_eq!(apply(&span, &ledger), span);

    let repeated = repeated_lines(count, &distinct_shape(0));
    let repeated_units = split_span(&repeated);
    let mut wide = new_ledger(&repeated_units);
    let flood = template_groups(&repeated, &mut wide, 3, &mut scratch);
    assert!(
        !flood.degraded,
        "one distinct template cannot fill the table"
    );
    assert_eq!(flood.stats.template_groups, 1);
    assert_eq!(flood.forms.len(), count);
    assert_eq!(flood.forms.id(0), flood.forms.id(count - 1));
    assert_eq!(wide.commits().len(), 1);
    assert_eq!(wide.commits()[0].members(), count);
}

#[test]
fn empty_single_unit_and_over_cap_spans_commit_nothing() {
    let mut scratch = Scratch::default();
    let empty: &[u8] = b"";
    let empty_units = split_span(empty);
    let mut ledger = new_ledger(&empty_units);
    let out = template_groups(empty, &mut ledger, 3, &mut scratch);
    assert!(!out.degraded);
    assert_eq!(out.stats, StageStats::default());
    assert!(out.forms.is_empty());
    assert_eq!(out.forms.len(), 0);

    let single = br"only one line 2026-08-26T10:00:00Z";
    let single_units = split_span(single);
    let mut ledger = new_ledger(&single_units);
    let out = template_groups(single, &mut ledger, 3, &mut scratch);
    assert_eq!(out.stats, StageStats::default());
    assert_eq!(out.forms.len(), 1);
    assert_eq!(out.forms.masked(0), b"only one line <ts>");

    let wall = vec![b'z'; MAX_LINE_BYTES + 1];
    let wall_units = split_span(&wall);
    assert_eq!(wall_units.len(), 1);
    assert!(!wall_units[0].eligible);
    let mut ledger = new_ledger(&wall_units);
    let out = template_groups(&wall, &mut ledger, 3, &mut scratch);
    assert_eq!(out.stats, StageStats::default());
    assert_eq!(out.forms.len(), 1);
    assert_eq!(out.forms.masked(0), &wall[..]);
    assert!(ledger.is_free(0..1));
}

#[test]
fn the_scratch_is_reused_and_never_grows_with_the_line_count() {
    let many: Vec<String> = (0..2000)
        .map(|index| {
            format!(
                r"2026-08-26T10:00:{:02}Z {} svc 10.0.0.{} took {}ms seq={index}",
                index % 60,
                LEVELS[index / 5 % LEVELS.len()],
                index % 256,
                1 + index % 900
            )
        })
        .collect();
    let borrowed: Vec<&[u8]> = many.iter().map(|line| line.as_bytes()).collect();
    let span = span_with(br"\n", &borrowed);
    let units = split_span(&span);
    let widest = units.iter().map(|unit| unit.range.len()).max().unwrap();
    let mut scratch = Scratch::with_capacity(widest, widest);
    let mut ledger = new_ledger(&units);
    let out = template_groups(&span, &mut ledger, 3, &mut scratch);
    assert!(
        out.stats.template_groups > 3,
        "the generator produced no groups"
    );
    assert_eq!(scratch.reserved(), (widest, widest));
    let few = span_with(
        br"\n",
        &[many[0].as_bytes(), many[1].as_bytes(), many[2].as_bytes()],
    );
    let few_units = split_span(&few);
    let mut small = new_ledger(&few_units);
    assert_eq!(
        template_groups(&few, &mut small, 3, &mut scratch)
            .stats
            .template_groups,
        1
    );
    assert_eq!(scratch.reserved(), (widest, widest));
    let mut grown = Scratch::default();
    let mut other = new_ledger(&units);
    let other_out = template_groups(&span, &mut other, 3, &mut grown);
    let mut reference = new_ledger(&units);
    let reference_out = template_groups(&span, &mut reference, 3, &mut scratch);
    assert_eq!(other_out, reference_out);
    assert_eq!(other.commits(), ledger.commits());
    assert!(grown.reserved().0 <= 2 * widest);
    assert!(grown.reserved().1 <= 2 * widest);
}

#[test]
fn template_groups_are_deterministic_over_a_generated_span() {
    let span = generated_span(400);
    let units = split_span(&span);
    let mut exact = new_ledger(&units);
    let mut ws = new_ledger(&units);
    let mut ws_scratch = WsScratch::default();
    assert_eq!(exact_runs(&span, &mut exact, 3), StageStats::default());
    assert_eq!(
        ws_runs(&span, &mut ws, 3, &mut ws_scratch),
        StageStats::default()
    );
    let mut first = new_ledger(&units);
    let mut second = new_ledger(&units);
    let mut scratch = Scratch::default();
    let mut other = Scratch::with_capacity(0, 0);
    let left = template_groups(&span, &mut first, 3, &mut scratch);
    let right = template_groups(&span, &mut second, 3, &mut other);
    assert_eq!(left.forms, right.forms);
    assert_eq!(left.stats, right.stats);
    assert!(
        left.stats.template_groups > 3,
        "generator produced no groups"
    );
    assert_eq!(left.stats.groups_collapsed, left.stats.template_groups);
    assert_eq!(left.stats.exact_runs, 0);
    assert_eq!(left.stats.ws_runs, 0);
    assert_eq!(left.stats.block_repeats, 0);
    assert_eq!(left.stats.templated_blocks, 0);
    assert_eq!(first.commits(), second.commits());
    assert_eq!(apply(&span, &first), apply(&span, &second));
    assert_masked_domain_forms(&span, &units, &left.forms);
    for left_unit in 0..units.len() {
        for right_unit in 0..units.len() {
            assert_eq!(
                left.forms.same(left_unit, right_unit),
                left.forms.masked(left_unit) == left.forms.masked(right_unit),
                "{left_unit}/{right_unit}"
            );
            if left.forms.id(left_unit) == left.forms.id(right_unit) {
                assert_eq!(
                    left.forms.masked(left_unit),
                    left.forms.masked(right_unit),
                    "id equality must imply masked byte equality"
                );
            }
        }
    }
    for commit in first.commits() {
        assert_removal_invariant(&units, commit);
    }
    let again = template_groups(&span, &mut first, 3, &mut scratch);
    assert_eq!(again.stats, StageStats::default());
    assert_eq!(again.forms, left.forms);
    assert_eq!(first.commits(), second.commits());
}

#[test]
fn a_template_group_is_committed_through_the_ledger_gate() {
    let span = span_with(br"\n", &[L0, L1, L2]);
    let units = split_span(&span);
    let mut ledger = new_ledger(&units);
    assert!(matches!(
        ledger.try_commit(Proposal::run(1..3, CommitKind::TemplateGroup)),
        CommitOutcome::Committed(_)
    ));
    let mut scratch = Scratch::default();
    let out = template_groups(&span, &mut ledger, 3, &mut scratch);
    assert_eq!(out.stats, StageStats::default());
    assert_eq!(ledger.commits().len(), 1);
    assert_eq!(ledger.commits()[0].first, 1);
    assert!(!ledger.is_committed(0));
    assert_eq!(out.forms.len(), 3);
    assert_eq!(out.forms.id(0), out.forms.id(2));
}

#[test]
fn the_templ_module_has_no_forbidden_determinism_inputs() {
    let source = include_str!("../src/detect/templ.rs");
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
        assert!(
            !source.contains(banned),
            "template groups must not use {banned}"
        );
    }
    assert!(source.contains("mask_into"));
    assert!(source.contains("normalize_into"));
    assert!(source.contains("FingerprintTable::for_keys"));
    assert!(source.contains("insert_hashed"));
    assert!(source.contains("Proposal::run(at..end, CommitKind::TemplateGroup)"));
}
