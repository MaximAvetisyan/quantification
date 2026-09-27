#[path = "adversarial_fixtures.rs"]
mod fixtures;

use std::time::{Duration, Instant};

use quantification_core::config::{
    MAX_BLOCK_LINES, MAX_LINE_BYTES, MAX_RECORD_BYTES, MIN_BLOCK_LINES, MarkerStyle, RawOptions,
    ResolvedOptions, resolve,
};
use quantification_core::detect::blocks::{Scratch, repeated_blocks};
use quantification_core::detect::templ::{Forms, Scratch as TemplScratch};
use quantification_core::detect::templ_blocks::{Scratch as BlockScratch, templated_blocks};
use quantification_core::fingerprint::{FingerprintTable, Insert, MAX_SLOTS, fingerprint};
use quantification_core::ledger::Ledger;
use quantification_core::locator::{NoopReason, SpanClass, locate_as};
use quantification_core::pipeline::{Compressor, Stats};
use quantification_core::sniff::{Schema, sniff};
use quantification_core::stage1::{Split, split_span_counted};
use quantification_core::wsnorm::Column;

const UNICODE: MarkerStyle = MarkerStyle::Unicode;
const PERIOD: usize = 129;
const STAGE5_FACTOR: u64 = (MAX_BLOCK_LINES - MIN_BLOCK_LINES + 1) as u64;
const STAGE7_FACTOR: u64 = MAX_BLOCK_LINES as u64;

fn options() -> ResolvedOptions {
    resolve(&RawOptions::default()).expect("the default options resolve")
}

fn compress(payload: &[u8]) -> (Stats, Vec<u8>, Duration) {
    let mut compressor = Compressor::new();
    let mut out = Vec::new();
    let start = Instant::now();
    let stats = compressor.compress(payload, &options(), &mut out);
    (stats, out, start.elapsed())
}

fn bounded(name: &str, payload: &[u8], limit_ms: u128) -> (Stats, Vec<u8>, Duration) {
    let (stats, out, elapsed) = compress(payload);
    assert!(
        elapsed.as_millis() <= limit_ms,
        "{name} took {elapsed:?} against its {limit_ms} ms budget on {} bytes",
        payload.len()
    );
    (stats, out, elapsed)
}

fn linear(name: &str, small_ms: u128, large_ms: u128, factor: u128, slack_ms: u128) {
    assert!(
        large_ms <= factor * small_ms + slack_ms,
        "{name} is not linear: {small_ms} ms for the small payload, {large_ms} ms for twice the units"
    );
}

fn user_span(payload: &[u8]) -> (Vec<u8>, Split) {
    let located = locate_as(payload, Schema::Chat, options().scope_policy);
    assert!(
        !located.degraded(),
        "the payload is a located chat document"
    );
    assert_eq!(located.spans.len(), 1, "one eligible user span");
    let span = &located.spans[0];
    assert_eq!(span.class, SpanClass::User);
    let bytes = payload[span.start..span.end].to_vec();
    let split = split_span_counted(&bytes, UNICODE);
    (bytes, split)
}

fn stage5_work(payload: &[u8]) -> (u64, u64, u64, bool) {
    let (bytes, split) = user_span(payload);
    let mut ledger = Ledger::new(&split.units, UNICODE);
    let mut column = Column::default();
    let mut line = Vec::new();
    column.build(&bytes, ledger.units(), &mut line);
    let forms = Forms::build(&column, ledger.units(), &mut TemplScratch::default());
    let mut scratch = Scratch::default();
    repeated_blocks(
        &column,
        forms.as_ref(),
        &mut ledger,
        2,
        MAX_BLOCK_LINES,
        &mut scratch,
    );
    let work = scratch.work();
    (
        work.compares,
        work.verifications,
        work.scanned,
        !scratch.degraded(),
    )
}

fn stage7_work(payload: &[u8]) -> (u64, u64, u64, bool) {
    let (bytes, split) = user_span(payload);
    let mut ledger = Ledger::new(&split.units, UNICODE);
    let mut column = Column::default();
    let mut line = Vec::new();
    column.build(&bytes, ledger.units(), &mut line);
    let forms = Forms::build(&column, ledger.units(), &mut TemplScratch::default());
    let mut scratch = BlockScratch::default();
    templated_blocks(forms.as_ref(), &mut ledger, MAX_BLOCK_LINES, &mut scratch);
    let work = scratch.work();
    (
        work.compares,
        work.verifications,
        work.scanned,
        forms.is_some(),
    )
}

fn capped(name: &str, work: (u64, u64, u64, bool), lines: u64, factor: u64) {
    let (compares, verifications, scanned, healthy) = work;
    assert!(healthy, "{name} did not reach the detectors at all");
    assert!(
        compares <= factor * lines,
        "{name}: {compares} compares for {lines} units is past the {factor} per unit cap"
    );
    assert!(
        scanned <= lines,
        "{name}: {scanned} scanned for {lines} units"
    );
    assert!(
        verifications <= compares,
        "{name}: {verifications} verifying memcmps for {compares} compares is past the cap"
    );
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn line_breaks(span: &[u8]) -> usize {
    [
        br"\n".as_slice(),
        br"\u000A".as_slice(),
        br"\u000a".as_slice(),
    ]
    .iter()
    .map(|escape| count(span, escape))
    .sum()
}

#[test]
fn every_generator_is_a_pure_function_of_its_arguments() {
    for case in fixtures::suite() {
        let again = fixtures::suite()
            .into_iter()
            .find(|other| other.name == case.name)
            .expect("the case is generated again");
        assert_eq!(
            again.payload, case.payload,
            "{} is not reproducible",
            case.name
        );
        assert!(
            sniff(&case.payload).is_some(),
            "{} is not a recognized document",
            case.name
        );
    }
}

#[test]
fn a_unique_line_flood_passes_through_with_capped_work() {
    let payload = fixtures::unique_lines(9_000);
    let (stats, out, small) = bounded("unique-lines", &payload, 400);
    assert!(
        !stats.degraded,
        "9 000 unique units are under the table cap"
    );
    assert_eq!(stats.noop_reason, None);
    assert_eq!(out, payload, "nothing is committed, so nothing changes");
    assert_eq!(stats.exact_runs + stats.ws_runs, 0);
    assert_eq!(stats.block_repeats + stats.template_groups, 0);
    let (_, split) = user_span(&payload);
    assert_eq!(split.units.len(), 9_000);
    assert!(split.units.iter().all(|unit| unit.eligible));
    assert_eq!(split.record_splits, 0);
    let work = stage5_work(&payload);
    capped("unique-lines", work, 9_000, STAGE5_FACTOR);
    capped(
        "unique-lines stage 7",
        stage7_work(&payload),
        9_000,
        STAGE7_FACTOR,
    );
    let (_, _, large) = compress(&fixtures::unique_lines(18_000));
    linear("unique-lines", small.as_millis(), large.as_millis(), 3, 250);
}

#[test]
fn a_giant_line_never_reaches_the_detectors() {
    let payload = fixtures::giant_line(200_000);
    let (stats, out, _) = bounded("giant-line", &payload, 300);
    assert!(!stats.degraded);
    assert_eq!(out, payload);
    assert_eq!(stats.exact_runs + stats.ws_runs, 0);
    let (span, split) = user_span(&payload);
    assert_eq!(line_breaks(&span), 1, "the whole span is one line");
    assert_eq!(split.units.len(), 1, "one over-cap line, one unit");
    assert_eq!(split.record_splits, 1, "stage 1b saw it once");
    assert!(
        !split.units[0].eligible,
        "an over-cap line with no separator stays verbatim"
    );
    assert!(split.units[0].range.len() > MAX_RECORD_BYTES);
    assert_eq!(stage5_work(&payload), (0, 0, 0, true), "no work at all");
}

#[test]
fn a_periodic_payload_stays_inside_the_capped_window_work() {
    let payload = fixtures::periodic_units(1_200, PERIOD);
    let (stats, out, small) = bounded("periodic-units", &payload, 900);
    assert!(!stats.degraded);
    assert_eq!(
        out, payload,
        "a period of 129 hides every window of at most 64 lines"
    );
    assert_eq!(
        stats.block_repeats, 0,
        "no window shorter than the period can match"
    );
    let (_, split) = user_span(&payload);
    assert_eq!(split.units.len(), 1_200);
    let work = stage5_work(&payload);
    capped("periodic-units", work, 1_200, STAGE5_FACTOR);
    assert_eq!(
        work.1, 0,
        "the KMP worst case never reaches a verifying memcmp"
    );
    assert!(
        work.0 > 1_200,
        "{} compares for 1 200 units: the fixture is not periodic any more",
        work.0
    );
    let half = stage5_work(&fixtures::periodic_units(600, PERIOD));
    let slack = 2 * MAX_BLOCK_LINES as u64 * MAX_BLOCK_LINES as u64;
    assert!(
        work.0 + work.2 <= 2 * (half.0 + half.2) + slack,
        "twice the units must not cost more than twice the steps"
    );
    let (_, _, large) = compress(&fixtures::periodic_units(2_400, PERIOD));
    linear(
        "periodic-units",
        small.as_millis(),
        large.as_millis(),
        3,
        250,
    );
}

#[test]
fn deeply_nested_arrays_stay_bounded_and_still_group() {
    let payload = fixtures::nested_arrays(500, 3);
    let (stats, out, _) = bounded("nested-arrays", &payload, 300);
    assert!(!stats.degraded);
    assert!(stats.exact_runs > 0, "the closing tail repeats and groups");
    assert!(out.len() < payload.len());
    assert!(
        out.len() > payload.len() / 2,
        "only the repeated closing tail collapses"
    );
    let (_, split) = user_span(&payload);
    assert_eq!(
        split.units.len(),
        1_504,
        "1 500 opening lines and 4 closing ones"
    );
    assert_eq!(sniff(&out), Some(Schema::Chat));
    let reparse = locate_as(&out, Schema::Chat, options().scope_policy);
    assert!(
        !reparse.degraded(),
        "the spliced output is still valid json"
    );
}

#[test]
fn a_deep_envelope_degrades_at_the_json_depth_cap() {
    let at_cap = fixtures::deep_envelope(60);
    let located = locate_as(&at_cap, Schema::Chat, options().scope_policy);
    assert_eq!(located.spans.len(), 1, "60 frames still fit under the cap");
    let over = fixtures::deep_envelope(96);
    assert_eq!(
        locate_as(&over, Schema::Chat, options().scope_policy).noop_reason,
        Some(NoopReason::Malformed)
    );
    let (stats, out, _) = bounded("deep-envelope", &over, 50);
    assert!(stats.degraded);
    assert_eq!(
        out, over,
        "a document past the cap is a byte-for-byte pass-through"
    );
    let (cap_stats, cap_out, _) = bounded("deep-envelope-at-cap", &at_cap, 50);
    assert!(!cap_stats.degraded);
    assert_eq!(cap_out, at_cap);
}

#[test]
fn a_flood_of_tiny_messages_stays_linear_in_messages() {
    let payload = fixtures::tiny_messages(20_000);
    let (stats, out, small) = bounded("tiny-messages", &payload, 900);
    assert!(!stats.degraded);
    assert_eq!(out, payload, "one unit per span means nothing to group");
    let located = locate_as(&payload, Schema::Chat, options().scope_policy);
    assert_eq!(
        located.spans.len(),
        10_000,
        "half the messages are user class"
    );
    assert!(
        located
            .spans
            .iter()
            .all(|span| span.class == SpanClass::User)
    );
    let (_, _, large) = compress(&fixtures::tiny_messages(40_000));
    linear(
        "tiny-messages",
        small.as_millis(),
        large.as_millis(),
        3,
        250,
    );
}

#[test]
fn collision_neighbours_merge_only_where_memcmp_verifies() {
    let payload = fixtures::collision_neighbors(200);
    let (stats, out, _) = bounded("collision-neighbors", &payload, 300);
    assert!(!stats.degraded);
    assert_eq!(
        stats.template_groups, 200,
        "one group per masked-equal triple"
    );
    assert_eq!(stats.exact_runs, 0);
    for group in 0..200 {
        for member in 0..3 {
            let line = fixtures::neighbor_line(group, member);
            assert_eq!(count(&payload, &line), 1, "the fixture built it once");
            assert_eq!(
                count(&out, &line),
                1,
                "a byte-different neighbour of group {group} was merged"
            );
        }
    }
}

#[test]
fn a_collision_pressure_table_never_conflates_its_neighbours() {
    let keys = fixtures::same_slot_keys(8, 64);
    assert_eq!(keys.len(), 8);
    let mut bytes = Vec::new();
    let mut ranges = Vec::new();
    let mut at = 0usize;
    for key in &keys {
        bytes.extend_from_slice(key);
        ranges.push(at..at + key.len());
        at += key.len();
    }
    let mut hashes: Vec<u128> = keys.iter().map(|key| fingerprint(key)).collect();
    hashes.sort_unstable();
    let distinct = hashes.len();
    hashes.dedup();
    assert_eq!(
        hashes.len(),
        distinct,
        "the 128-bit digests never collide here"
    );
    let mut table = fixtures::table_for(bytes.len());
    assert_eq!(
        table.slots(),
        64,
        "eight keys share one start slot in 64 slots"
    );
    for (index, range) in ranges.iter().enumerate() {
        assert_eq!(table.insert(&bytes, range.clone(), index), Insert::New);
    }
    for (index, range) in ranges.iter().enumerate() {
        assert_eq!(table.find(&bytes, range.clone()), Some(index));
    }
    assert_eq!(table.len(), 8);
    let mut twin = bytes.clone();
    twin[ranges[0].start] += 1;
    assert_eq!(table.insert(&twin, ranges[0].clone(), 99), Insert::New);
    assert_eq!(table.find(&twin, ranges[0].clone()), Some(99));
    assert_eq!(
        table.find(&bytes, ranges[0].clone()),
        Some(0),
        "the twin never shadows its neighbour"
    );
}

#[test]
fn the_fingerprint_table_caps_itself_and_then_refuses_to_grow() {
    let mut table = FingerprintTable::for_keys(1 << 30);
    assert_eq!(table.slots(), MAX_SLOTS, "the slot count is capped");
    let mut keys = Vec::new();
    let mut at = 0usize;
    let limit = MAX_SLOTS * 3 / 4 + 2;
    let mut full_at = None;
    for index in 0..limit {
        keys.extend_from_slice(format!("k{index:016}").as_bytes());
        if table.insert(&keys, at..at + 17, index) == Insert::Full {
            full_at = Some(index);
            break;
        }
        at += 17;
    }
    assert_eq!(full_at, Some(MAX_SLOTS * 3 / 4), "the 75% rule is the cap");
    assert!(table.is_full());
    assert_eq!(table.slots(), MAX_SLOTS, "a full table never grows");
}

#[test]
fn maximal_density_record_dumps_segment_and_collapse() {
    let payload = fixtures::dense_records(9_000, false);
    let (stats, out, _) = bounded("dense-records", &payload, 600);
    assert!(!stats.degraded);
    assert_eq!(stats.record_splits, 1, "the dump is one over-cap line");
    assert_eq!(stats.exact_runs, 1, "9 000 identical records are one run");
    assert!(out.len() < 200, "{} bytes out", out.len());
    let (span, split) = user_span(&payload);
    assert_eq!(
        line_breaks(&span),
        0,
        "the dump carries no line separator at all"
    );
    assert!(
        span.len() > MAX_LINE_BYTES,
        "{} bytes on one line",
        span.len()
    );
    assert_eq!(
        split.units.len(),
        9_000,
        "one unit per record, the brackets ride along"
    );
    let longest = split
        .units
        .iter()
        .map(|unit| unit.range.len())
        .max()
        .unwrap();
    assert!(longest <= MAX_RECORD_BYTES, "{longest} bytes in a record");
    let stride = span.len() / 9_000;
    assert!(
        stride <= 21,
        "a separator every {stride} bytes is maximal density"
    );
    assert_eq!(
        count(&span, br"},{"),
        8_999,
        "one separator per record boundary"
    );
}

#[test]
fn a_dense_dump_of_unique_records_groups_only_on_the_masked_form() {
    let payload = fixtures::dense_records(9_000, true);
    let (stats, out, _) = bounded("dense-records-unique", &payload, 900);
    assert!(!stats.degraded);
    assert_eq!(stats.record_splits, 1);
    assert_eq!(stats.exact_runs, 0, "no two records are byte-equal");
    assert_eq!(
        stats.template_groups, 1,
        "the masked forms are one template"
    );
    assert!(out.len() < 200, "{} bytes out", out.len());
    let (_, split) = user_span(&payload);
    assert_eq!(split.units.len(), 9_000);
    assert!(
        split
            .units
            .iter()
            .all(|unit| unit.range.len() <= MAX_RECORD_BYTES)
    );
    capped(
        "dense-records-unique",
        stage5_work(&payload),
        9_000,
        STAGE5_FACTOR,
    );
}

#[test]
fn the_whole_adversarial_suite_stays_inside_the_stage_budgets() {
    for case in fixtures::suite() {
        let name = case.name;
        let (stats, out, elapsed) = compress(&case.payload);
        assert_eq!(stats.bytes_in, case.payload.len() as u64, "{name}");
        assert!(out.len() <= case.payload.len(), "{name} grew");
        assert!(elapsed.as_secs() < 10, "{name} took {elapsed:?}");
        println!(
            "{name} bytes={} out={} degraded={} exact={} ws={} block={} tgroup={} tblock={} splits={} in {elapsed:?}",
            case.payload.len(),
            stats.bytes_out,
            stats.degraded,
            stats.exact_runs,
            stats.ws_runs,
            stats.block_repeats,
            stats.template_groups,
            stats.templated_blocks,
            stats.record_splits,
        );
    }
}

#[test]
#[cfg(feature = "bench_stages")]
fn a_unique_line_flood_past_the_table_cap_degrades_to_a_pass_through() {
    let payload = fixtures::unique_lines(200_000);
    let (stats, out, elapsed) = bounded("unique-lines-over-cap", &payload, 30_000);
    assert!(stats.degraded, "the fingerprint table filled at its cap");
    assert_eq!(
        stats.noop_reason, None,
        "the degradation is the table cap, not a parse failure"
    );
    assert_eq!(
        out, payload,
        "a degraded span is a byte-for-byte pass-through"
    );
    assert_eq!(
        stats.block_repeats, 0,
        "the degraded stage committed nothing"
    );
    println!(
        "unique-lines past the cap: {elapsed:?} on {} bytes",
        payload.len()
    );
}

#[test]
#[cfg(feature = "bench_stages")]
fn a_dense_dump_past_the_table_cap_degrades_to_a_pass_through() {
    let payload = fixtures::dense_records(200_000, true);
    let (stats, out, elapsed) = bounded("dense-records-over-cap", &payload, 30_000);
    assert!(stats.degraded);
    assert_eq!(out, payload);
    println!(
        "dense-records past the cap: {elapsed:?} on {} bytes",
        payload.len()
    );
}

#[test]
#[cfg(feature = "bench_stages")]
fn a_million_tiny_messages_stay_bounded() {
    let payload = fixtures::tiny_messages(1_000_000);
    let (stats, out, elapsed) = bounded("million-tiny-messages", &payload, 60_000);
    assert!(!stats.degraded);
    assert_eq!(out, payload);
    let located = locate_as(&payload, Schema::Chat, options().scope_policy);
    assert_eq!(located.spans.len(), 500_000);
    println!(
        "a million tiny messages: {elapsed:?} on {} bytes",
        payload.len()
    );
}
