use std::hint::black_box;
use std::time::Duration;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use quantification_core::config::{MarkerStyle, RawOptions, ResolvedOptions, ScopePolicy, resolve};
use quantification_core::detect::{blocks, exact, templ, templ_blocks, wsruns};
use quantification_core::ledger::{Commit, Ledger};
use quantification_core::locator::{Span, locate_into};
use quantification_core::perf_payload::{TARGET_BYTES, log_heavy_chat};
use quantification_core::pipeline::Compressor;
use quantification_core::sniff::{Schema, sniff};
use quantification_core::splice::splice_into;
use quantification_core::stage1::Unit;
use quantification_core::stage1::split_span_counted;

const MIN_GROUP_SIZE: u32 = 3;
const MIN_BLOCK_LINES: u32 = 2;
const MAX_BLOCK_LINES: u32 = 64;

struct Fixture {
    payload: Vec<u8>,
    span: Vec<u8>,
    options: ResolvedOptions,
    commits: Vec<Commit>,
}

fn fixture() -> Fixture {
    let payload = log_heavy_chat(TARGET_BYTES);
    let options = resolve(&RawOptions::default()).expect("defaults resolve");
    let mut compressor = Compressor::new();
    let mut out = Vec::new();
    compressor.compress(&payload, &options, &mut out);
    let commits = compressor.commits().to_vec();
    let span = eligible_span(&payload, &options);
    Fixture {
        payload,
        span,
        options,
        commits,
    }
}

fn eligible_span(payload: &[u8], options: &ResolvedOptions) -> Vec<u8> {
    let mut spans: Vec<Span> = Vec::new();
    let located = locate_into(payload, Schema::Chat, options.scope_policy, &mut spans);
    assert!(located.is_none(), "the fixture must not degrade");
    let first = spans.first().expect("the fixture has one eligible span");
    payload[first.start..first.end].to_vec()
}

fn units_of(span: &[u8], style: MarkerStyle) -> Vec<Unit> {
    split_span_counted(span, style).units
}

fn forms_of(span: &[u8], units: &[Unit]) -> templ::Forms {
    let mut scratch = templ::Scratch::default();
    templ::Forms::build(span, units, &mut scratch).expect("the fixture table never fills")
}

fn bench_locate(c: &mut Criterion) {
    let f = fixture();
    let mut group = c.benchmark_group("locate");
    group.bench_function("schema_sniff", |b| {
        b.iter(|| black_box(sniff(black_box(&f.payload))))
    });
    group.bench_function("span_locate", |b| {
        b.iter_batched(
            Vec::new,
            |mut spans: Vec<Span>| {
                locate_into(
                    black_box(&f.payload),
                    Schema::Chat,
                    ScopePolicy::UserContent,
                    &mut spans,
                )
            },
            BatchSize::LargeInput,
        )
    });
    group.finish();
}

fn bench_compact(c: &mut Criterion) {
    let f = fixture();
    let style = MarkerStyle::Unicode;
    let span = &f.span;
    let mut group = c.benchmark_group("compact");
    group.bench_function("stage1_split", |b| {
        b.iter(|| black_box(split_span_counted(black_box(span), style)))
    });
    group.bench_function("ledger_setup", |b| {
        b.iter_batched(
            || units_of(span, style),
            |units| {
                let ledger = Ledger::new(black_box(&units), style);
                black_box(ledger.commits().len())
            },
            BatchSize::LargeInput,
        )
    });
    group.bench_function("stage3_exact_runs", |b| {
        b.iter_batched(
            || units_of(span, style),
            |units| {
                let mut ledger = Ledger::new(&units, style);
                black_box(exact::exact_runs(span, &mut ledger, MIN_GROUP_SIZE))
            },
            BatchSize::LargeInput,
        )
    });
    group.bench_function("stage4_ws_runs", |b| {
        b.iter_batched(
            || units_of(span, style),
            |units| {
                let mut ledger = Ledger::new(&units, style);
                let mut scratch = wsruns::Scratch::default();
                black_box(wsruns::ws_runs(
                    span,
                    &mut ledger,
                    MIN_GROUP_SIZE,
                    &mut scratch,
                ))
            },
            BatchSize::LargeInput,
        )
    });
    group.bench_function("stage5_blocks", |b| {
        b.iter_batched(
            || {
                let units = units_of(span, style);
                let forms = forms_of(span, &units);
                (units, forms)
            },
            |(units, forms)| {
                let mut ledger = Ledger::new(&units, style);
                let mut scratch = blocks::Scratch::new();
                black_box(blocks::repeated_blocks(
                    span,
                    Some(&forms),
                    &mut ledger,
                    MIN_BLOCK_LINES,
                    MAX_BLOCK_LINES,
                    &mut scratch,
                ))
            },
            BatchSize::LargeInput,
        )
    });
    group.bench_function("stage6_masked_forms", |b| {
        b.iter_batched(
            || units_of(span, style),
            |units| {
                let mut scratch = templ::Scratch::default();
                black_box(templ::Forms::build(black_box(span), &units, &mut scratch))
            },
            BatchSize::LargeInput,
        )
    });
    group.bench_function("stage6_template_groups", |b| {
        b.iter_batched(
            || {
                let units = units_of(span, style);
                let forms = forms_of(span, &units);
                (units, forms)
            },
            |(units, forms)| {
                let mut ledger = Ledger::new(&units, style);
                black_box(templ::template_groups(&forms, &mut ledger, MIN_GROUP_SIZE))
            },
            BatchSize::LargeInput,
        )
    });
    group.bench_function("stage7_templated_blocks", |b| {
        b.iter_batched(
            || {
                let units = units_of(span, style);
                let forms = forms_of(span, &units);
                (units, forms)
            },
            |(units, forms)| {
                let mut ledger = Ledger::new(&units, style);
                let mut scratch = templ_blocks::Scratch::new();
                black_box(templ_blocks::templated_blocks(
                    Some(&forms),
                    &mut ledger,
                    MAX_BLOCK_LINES,
                    &mut scratch,
                ))
            },
            BatchSize::LargeInput,
        )
    });
    group.bench_function("stages1_7", |b| {
        let mut compressor = Compressor::new();
        b.iter(|| {
            compressor.reset_stage_times();
            black_box(compressor.compact_span_only(black_box(span), black_box(&f.options)))
        })
    });
    group.finish();
}

fn bench_splice(c: &mut Criterion) {
    let f = fixture();
    let mut out = Vec::with_capacity(f.payload.len());
    let mut group = c.benchmark_group("splice");
    group.bench_function("8mib_copy_no_commits", |b| {
        b.iter(|| {
            let out = splice_into(black_box(&f.payload), &[], &mut out);
            black_box(out.len())
        })
    });
    group.bench_function("8mib_splice_with_commits", |b| {
        b.iter(|| {
            let out = splice_into(black_box(&f.payload), black_box(&f.commits), &mut out);
            black_box(out.len())
        })
    });
    group.finish();
}

fn bench_end_to_end(c: &mut Criterion) {
    let f = fixture();
    let mut out = Vec::new();
    let mut compressor = Compressor::new();
    compressor.compress(&f.payload, &f.options, &mut out);
    let mut group = c.benchmark_group("end_to_end");
    group.bench_function("compress_8mib", |b| {
        b.iter(|| {
            let stats = compressor.compress(black_box(&f.payload), black_box(&f.options), &mut out);
            black_box(stats.bytes_out)
        })
    });
    group.finish();
}

fn configured() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(8))
}

criterion_group! {
    name = locate;
    config = configured();
    targets = bench_locate
}

criterion_group! {
    name = compact;
    config = configured();
    targets = bench_compact
}

criterion_group! {
    name = splice;
    config = configured();
    targets = bench_splice
}

criterion_group! {
    name = end_to_end;
    config = configured();
    targets = bench_end_to_end
}

criterion_main!(locate, compact, splice, end_to_end);
