use std::time::Instant;

use quantification_core::config::{RawOptions, ResolvedOptions, resolve};
use quantification_core::locator::{Span, locate_into};
use quantification_core::perf_payload::{TARGET_BYTES, log_heavy_chat};
use quantification_core::pipeline::{Compressor, Stage, StageTimes, Stats};
use quantification_core::sniff::Schema;
use quantification_core::splice::splice_into;
use quantification_core::stage1::split_span_counted;

const WARMUP: usize = 3;
const DEFAULT_ITERS: usize = 30;
const DETECT_BUDGET_NS: u64 = 20_000_000;
const DETECT_FLOOR_MB_S: u64 = 400;
const COMPACT_BUDGET_NS: u64 = 50_000_000;
const COMPACT_FLOOR_MB_S: u64 = 160;
const SPLICE_BUDGET_NS: u64 = 10_000_000;
const AGGREGATE_FLOOR_MB_S: u64 = 100;
const R2_BUDGET_NS: u64 = 80_000_000;

#[derive(Clone)]
struct Sample {
    total_ns: u64,
    detect_ns: u64,
    compact_ns: u64,
    splice_ns: u64,
    times: StageTimes,
}

struct Report {
    payload_bytes: u64,
    output_bytes: u64,
    spans: usize,
    units: usize,
    iters: usize,
    p50: Sample,
    p99: Sample,
    copy_p50_ns: u64,
    copy_p99_ns: u64,
    stats: Stats,
    pass: Vec<String>,
    fail: Vec<String>,
}

fn main() {
    let (iters, json) = args();
    let report = measure(iters);
    print_report(&report);
    if let Some(path) = json {
        write_json(&report, &path);
    }
    if !report.fail.is_empty() {
        std::process::exit(1);
    }
}

fn args() -> (usize, Option<String>) {
    let mut iters = DEFAULT_ITERS;
    let mut json = None;
    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--iters" => {
                iters = argv
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(DEFAULT_ITERS);
            }
            "--json" => json = argv.next(),
            _ => {}
        }
    }
    (iters, json)
}

fn measure(iters: usize) -> Report {
    let options = resolve(&RawOptions::default()).expect("defaults resolve");
    let payload = log_heavy_chat(TARGET_BYTES);
    let mut compressor = Compressor::new();
    let mut out = Vec::new();
    for _ in 0..WARMUP {
        compressor.compress(&payload, &options, &mut out);
    }
    compressor.reset_stage_times();
    let mut samples = Vec::with_capacity(iters);
    let mut stats = Stats::default();
    for _ in 0..iters {
        let start = Instant::now();
        let run = compressor.compress(&payload, &options, &mut out);
        let total_ns = start.elapsed().as_nanos() as u64;
        samples.push(Sample {
            total_ns,
            detect_ns: run.elapsed_detect_ns,
            compact_ns: run.elapsed_compact_ns,
            splice_ns: run.elapsed_splice_ns,
            times: compressor.last_stage_times(),
        });
        stats = run;
        compressor.reset_stage_times();
    }
    let mut order: Vec<usize> = (0..samples.len()).collect();
    order.sort_by_key(|&at| samples[at].total_ns);
    let p50 = samples[order[rank(order.len(), 50)]].clone();
    let p99 = samples[order[rank(order.len(), 99)]].clone();
    let (copy_p50_ns, copy_p99_ns) = measure_copy(&payload, iters);
    let units = unit_count(&payload, &options);
    let spans = span_count(&payload, &options);
    let mut pass: Vec<String> = Vec::new();
    let mut fail = Vec::new();
    check(
        &mut pass,
        &mut fail,
        "non_vacuous",
        stats.groups_collapsed > 0
            && stats.exact_runs > 0
            && stats.ws_runs > 0
            && stats.block_repeats > 0
            && stats.template_groups > 0
            && stats.templated_blocks > 0
            && stats.record_splits > 0
            && !stats.degraded,
        &format!(
            "groups={} exact={} ws={} blocks={} templ={} templ_blocks={} record_splits={} degraded={}",
            stats.groups_collapsed,
            stats.exact_runs,
            stats.ws_runs,
            stats.block_repeats,
            stats.template_groups,
            stats.templated_blocks,
            stats.record_splits,
            stats.degraded
        ),
    );
    check(
        &mut pass,
        &mut fail,
        "aggregate_p50_floor_100MB_s",
        mbps(payload.len() as u64, p50.total_ns) >= AGGREGATE_FLOOR_MB_S,
        &format!("p50 {}", rate(payload.len() as u64, p50.total_ns)),
    );
    check(
        &mut pass,
        &mut fail,
        "detect_budget_20ms",
        p50.detect_ns <= DETECT_BUDGET_NS,
        &format!("p50 {} ns", p50.detect_ns),
    );
    check(
        &mut pass,
        &mut fail,
        "detect_floor_400MB_s",
        mbps(payload.len() as u64, p50.detect_ns) >= DETECT_FLOOR_MB_S,
        &format!("p50 {}", rate(payload.len() as u64, p50.detect_ns)),
    );
    check(
        &mut pass,
        &mut fail,
        "compact_budget_50ms",
        p50.compact_ns <= COMPACT_BUDGET_NS,
        &format!("p50 {} ns", p50.compact_ns),
    );
    check(
        &mut pass,
        &mut fail,
        "compact_floor_160MB_s",
        mbps(payload.len() as u64, p50.compact_ns) >= COMPACT_FLOOR_MB_S,
        &format!("p50 {}", rate(payload.len() as u64, p50.compact_ns)),
    );
    check(
        &mut pass,
        &mut fail,
        "splice_budget_10ms",
        p50.splice_ns <= SPLICE_BUDGET_NS && copy_p50_ns <= SPLICE_BUDGET_NS,
        &format!(
            "p50 {} ns in-pipeline, {copy_p50_ns} ns 8 MiB copy",
            p50.splice_ns
        ),
    );
    check(
        &mut pass,
        &mut fail,
        "r2_budget_80ms",
        p50.total_ns <= R2_BUDGET_NS,
        &format!("p50 {} ns", p50.total_ns),
    );
    Report {
        payload_bytes: payload.len() as u64,
        output_bytes: out.len() as u64,
        spans,
        units,
        iters,
        p50,
        p99,
        copy_p50_ns,
        copy_p99_ns,
        stats,
        pass,
        fail,
    }
}

fn measure_copy(payload: &[u8], iters: usize) -> (u64, u64) {
    let mut out = Vec::with_capacity(payload.len());
    for _ in 0..WARMUP {
        out.clear();
        splice_into(payload, &[], &mut out);
    }
    let mut times = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        out.clear();
        splice_into(payload, &[], &mut out);
        times.push(start.elapsed().as_nanos() as u64);
    }
    times.sort_unstable();
    (times[rank(times.len(), 50)], times[rank(times.len(), 99)])
}

fn rank(len: usize, pct: u64) -> usize {
    ((pct * len as u64).div_ceil(100) as usize).saturating_sub(1)
}

fn mbps_x10(bytes: u64, ns: u64) -> u64 {
    bytes.saturating_mul(10_000) / ns.max(1)
}

fn mbps(bytes: u64, ns: u64) -> u64 {
    mbps_x10(bytes, ns) / 10
}

fn rate(bytes: u64, ns: u64) -> String {
    let x = mbps_x10(bytes, ns);
    format!("{}.{} MB/s", x / 10, x % 10)
}

fn per_mille(part: u64, whole: u64) -> String {
    let x = part.saturating_mul(1000) / whole.max(1);
    format!("{}.{}%", x / 10, x % 10)
}

fn located_spans(payload: &[u8], options: &ResolvedOptions) -> Vec<Span> {
    let mut spans = Vec::new();
    let noop = locate_into(payload, Schema::Chat, options.scope_policy, &mut spans);
    assert!(noop.is_none(), "the fixture must not degrade");
    spans
}

fn span_count(payload: &[u8], options: &ResolvedOptions) -> usize {
    located_spans(payload, options).len()
}

fn unit_count(payload: &[u8], options: &ResolvedOptions) -> usize {
    let spans = located_spans(payload, options);
    let first = *spans.first().expect("the fixture has an eligible span");
    let span = &payload[first.start..first.end];
    split_span_counted(span, options.marker_style).units.len()
}

fn check(pass: &mut Vec<String>, fail: &mut Vec<String>, name: &str, ok: bool, detail: &str) {
    if ok {
        pass.push(name.to_string());
    } else {
        fail.push(format!("{name}: {detail}"));
    }
}

fn print_report(r: &Report) {
    println!("quantification perf gate (DESIGN.md §8)");
    println!("hardware: {}", hardware());
    println!("affinity: {}", affinity());
    println!(
        "payload: {} bytes, {} eligible spans, {} units, {} iterations ({} warmup discarded)",
        r.payload_bytes, r.spans, r.units, r.iters, WARMUP
    );
    println!(
        "compression: {} -> {} bytes ({} of input), {} groups collapsed, not degraded",
        r.stats.bytes_in,
        r.stats.bytes_out,
        per_mille(r.output_bytes, r.payload_bytes),
        r.stats.groups_collapsed
    );
    println!();
    println!("| metric | p50 | p99 | §8 budget | floor | verdict |");
    println!("|---|---|---|---|---|---|");
    row(
        "aggregate (bytes-in / total core time)",
        r,
        r.p50.total_ns,
        r.p99.total_ns,
        &format!("<= {} ms (R2)", R2_BUDGET_NS / 1_000_000),
        &format!(">= {AGGREGATE_FLOOR_MB_S} MB/s"),
    );
    row(
        "schema sniff + span locate",
        r,
        r.p50.detect_ns,
        r.p99.detect_ns,
        &format!("<= {} ms", DETECT_BUDGET_NS / 1_000_000),
        &format!(">= {DETECT_FLOOR_MB_S} MB/s"),
    );
    row(
        "span compaction (stages 1-7)",
        r,
        r.p50.compact_ns,
        r.p99.compact_ns,
        &format!("<= {} ms", COMPACT_BUDGET_NS / 1_000_000),
        &format!(">= {COMPACT_FLOOR_MB_S} MB/s"),
    );
    out_row(
        "splice + stats (output bytes)",
        r,
        r.p50.splice_ns,
        r.p99.splice_ns,
        &format!("<= {} ms", SPLICE_BUDGET_NS / 1_000_000),
        "none",
    );
    row(
        "8 MiB splice copy (no commits)",
        r,
        r.copy_p50_ns,
        r.copy_p99_ns,
        &format!("<= {} ms", SPLICE_BUDGET_NS / 1_000_000),
        "none",
    );
    println!();
    println!("| §4.4 stage (in-pipeline, p50) | ns | MB/s | share |");
    println!("|---|---|---|---|");
    for stage in Stage::ALL {
        let ns = r.p50.times.get(stage);
        let share = 100 * ns / r.p50.compact_ns.max(1);
        println!(
            "| {} | {} | {} | {share}% |",
            stage.name(),
            ns,
            rate(r.payload_bytes, ns)
        );
    }
    let accounted = r.p50.times.total();
    let other = r.p50.compact_ns.saturating_sub(accounted);
    println!(
        "| compaction unattributed (ledger, merges, shifts) | {other} | {} | {}% |",
        rate(r.payload_bytes, other),
        100 * other / r.p50.compact_ns.max(1)
    );
    let overhead = r
        .p50
        .total_ns
        .saturating_sub(r.p50.detect_ns + r.p50.compact_ns + r.p50.splice_ns);
    println!(
        "| pipeline unattributed (stats assembly, options echo) | {overhead} | {} | |",
        rate(r.payload_bytes, overhead)
    );
    println!();
    for name in &r.pass {
        println!("PASS {name}");
    }
    for name in &r.fail {
        println!("FAIL {name}");
    }
    println!(
        "verdict: {}",
        if r.fail.is_empty() {
            "M3 PASS"
        } else {
            "M3 FAIL"
        }
    );
}

fn row(label: &str, r: &Report, p50: u64, p99: u64, budget: &str, floor: &str) {
    println!(
        "| {label} | {} ({}) | {} ({}) | {budget} | {floor} | |",
        ns_ms(p50),
        rate(r.payload_bytes, p50),
        ns_ms(p99),
        rate(r.payload_bytes, p99),
    );
}

fn out_row(label: &str, r: &Report, p50: u64, p99: u64, budget: &str, floor: &str) {
    println!(
        "| {label} | {} ({}) | {} ({}) | {budget} | {floor} | |",
        ns_ms(p50),
        rate(r.output_bytes, p50),
        ns_ms(p99),
        rate(r.output_bytes, p99),
    );
}

fn ns_ms(ns: u64) -> String {
    format!("{}.{:02} ms", ns / 1_000_000, (ns / 10_000) % 100)
}

fn hardware() -> String {
    let info = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let name = info
        .lines()
        .find(|line| line.starts_with("model name"))
        .and_then(|line| line.split(':').nth(1))
        .map(str::trim)
        .unwrap_or("unknown");
    format!(
        "{name}, {} logical cpus",
        std::thread::available_parallelism().map_or(0, |n| n.get())
    )
}

fn affinity() -> String {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .find(|line| line.starts_with("Cpus_allowed_list"))
        .map_or_else(|| "unknown".to_string(), |line| line.replace('\t', " "))
}

fn report_path(path: &str) -> std::path::PathBuf {
    let given = std::path::Path::new(path);
    if given.is_absolute() {
        return given.to_path_buf();
    }
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(given)
}

fn write_json(r: &Report, path: &str) {
    let hw = hardware();
    let stages: Vec<String> = Stage::ALL
        .iter()
        .map(|stage| {
            format!(
                "{{\"stage\":\"{}\",\"p50_ns\":{}}}",
                stage.name(),
                r.p50.times.get(*stage)
            )
        })
        .collect();
    let stages = stages.join(",");
    let json = format!(
        "{{\"hardware\":\"{hw}\",\"payload_bytes\":{},\"output_bytes\":{},\"spans\":{},\"units\":{},\"iters\":{},\
\"aggregate\":{{\"p50_ns\":{},\"p99_ns\":{},\"p50_mbs_x10\":{},\"p99_mbs_x10\":{}}},\
\"detect\":{{\"p50_ns\":{},\"p99_ns\":{}}},\"compact\":{{\"p50_ns\":{},\"p99_ns\":{}}},\
\"splice\":{{\"p50_ns\":{},\"p99_ns\":{},\"out_bytes\":{}}},\
\"copy8mib\":{{\"p50_ns\":{},\"p99_ns\":{}}},\"stages\":[{}],\
\"groups_collapsed\":{},\"degraded\":{},\"pass\":{:?},\"fail\":{:?},\"verdict\":\"{}\"}}",
        r.payload_bytes,
        r.output_bytes,
        r.spans,
        r.units,
        r.iters,
        r.p50.total_ns,
        r.p99.total_ns,
        mbps_x10(r.payload_bytes, r.p50.total_ns),
        mbps_x10(r.payload_bytes, r.p99.total_ns),
        r.p50.detect_ns,
        r.p99.detect_ns,
        r.p50.compact_ns,
        r.p99.compact_ns,
        r.p50.splice_ns,
        r.p99.splice_ns,
        r.output_bytes,
        r.copy_p50_ns,
        r.copy_p99_ns,
        stages,
        r.stats.groups_collapsed,
        r.stats.degraded,
        r.pass,
        r.fail,
        if r.fail.is_empty() { "PASS" } else { "FAIL" },
    );
    let path = report_path(path);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&path, json).expect("the report path is writable");
    println!("report: {}", path.display());
}
