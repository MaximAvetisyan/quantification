#![cfg(feature = "bench_stages")]

use quantification_core::config::{RawOptions, resolve};
use quantification_core::locator::{NoopReason, locate_as};
use quantification_core::perf_payload::{TARGET_BYTES, log_heavy_chat};
use quantification_core::pipeline::Compressor;
use quantification_core::sniff::{Schema, sniff};
use quantification_core::stage1::split_span_counted;

fn fixture() -> Vec<u8> {
    log_heavy_chat(TARGET_BYTES)
}

#[test]
fn the_fixture_is_deterministic_and_a_valid_chat_document() {
    let a = fixture();
    let b = fixture();
    assert_eq!(a, b, "the generator is a pure function of its target size");
    assert!(
        a.len() >= TARGET_BYTES,
        "{} bytes is the requested 8 MiB",
        a.len()
    );
    assert_eq!(sniff(&a), Some(Schema::Chat));
    let located = locate_as(
        &a,
        Schema::Chat,
        quantification_core::config::ScopePolicy::UserContent,
    );
    assert_eq!(located.noop_reason, None);
    assert!(!located.degraded());
    assert_eq!(located.spans.len(), 1, "one eligible user span");
    let span = &a[located.spans[0].start..located.spans[0].end];
    assert!(std::str::from_utf8(span).is_ok());
}

#[test]
fn the_fixture_fires_every_detector_and_degrades_nowhere() {
    let payload = fixture();
    let options = resolve(&RawOptions::default()).expect("defaults resolve");
    let mut compressor = Compressor::new();
    let mut out = Vec::new();
    let stats = compressor.compress(&payload, &options, &mut out);
    assert!(!stats.degraded, "the fixture must not degrade");
    assert_eq!(stats.noop_reason, None);
    assert!(
        stats.bytes_out < stats.bytes_in,
        "the fixture must compress"
    );
    assert!(stats.exact_runs > 0, "stage 3");
    assert!(stats.ws_runs > 0, "stage 4");
    assert!(stats.block_repeats > 0, "stage 5");
    assert!(stats.template_groups > 0, "stage 6");
    assert!(stats.templated_blocks > 0, "stage 7");
    assert!(stats.record_splits > 0, "stage 1b");
}

#[test]
fn the_fixture_exercises_stage1b_record_segmentation() {
    let payload = fixture();
    let options = resolve(&RawOptions::default()).expect("defaults resolve");
    let located = locate_as(&payload, Schema::Chat, options.scope_policy);
    let span = &payload[located.spans[0].start..located.spans[0].end];
    let split = split_span_counted(span, options.marker_style);
    let units = split.units;
    assert!(split.record_splits > 0, "an over-cap line is re-segmented");
    assert!(units.len() > 10_000, "{} units", units.len());
    let longest = units.iter().map(|unit| unit.range.len()).max().unwrap();
    assert!(longest < 65_536, "every unit is at or below max_line_bytes");
    assert!(
        !units.iter().any(|unit| !unit.eligible),
        "no unit carries a marker"
    );
}

#[test]
fn a_malformed_copy_of_the_fixture_degrades_instead_of_panicking() {
    let mut payload = fixture();
    let at = payload.len() / 2;
    payload.truncate(at);
    let options = resolve(&RawOptions::default()).expect("defaults resolve");
    let mut compressor = Compressor::new();
    let mut out = Vec::new();
    let stats = compressor.compress(&payload, &options, &mut out);
    assert!(stats.degraded);
    assert_eq!(stats.noop_reason, Some(NoopReason::Malformed));
    assert_eq!(out, payload);
}
