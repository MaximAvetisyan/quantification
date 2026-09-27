use std::ops::Range;
use std::time::Instant;

use crate::ccr::Sink;
use crate::config::{MAX_BLOCK_LINES, MIN_BLOCK_LINES, MarkerStyle, ResolvedOptions};
use crate::detect::{blocks, exact, templ, templ_blocks, wsruns};
use crate::fingerprint::marker_checksum;
use crate::ledger::{Commit, Ledger, StageStats};
use crate::locator::{NoopReason, Span, locate_into};
use crate::render::{self, resolve_style};
use crate::sniff::{self, Schema};
use crate::splice::splice_into;
use crate::stage1;
use crate::wsnorm;

pub const ALGO_VERSION: &str = "0.1.0";

#[cfg(feature = "bench_stages")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StageTimes {
    ns: [u64; 8],
}

#[cfg(feature = "bench_stages")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Stage {
    Split = 0,
    WsColumn = 1,
    ExactRuns = 2,
    WsRuns = 3,
    MaskedForms = 4,
    Blocks = 5,
    TemplateGroups = 6,
    TemplatedBlocks = 7,
}

#[cfg(feature = "bench_stages")]
impl Stage {
    pub const ALL: [Stage; 8] = [
        Self::Split,
        Self::WsColumn,
        Self::ExactRuns,
        Self::WsRuns,
        Self::MaskedForms,
        Self::Blocks,
        Self::TemplateGroups,
        Self::TemplatedBlocks,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Split => "stage1_split",
            Self::WsColumn => "prepass_ws_column",
            Self::ExactRuns => "stage3_exact_runs",
            Self::WsRuns => "stage4_ws_runs",
            Self::MaskedForms => "stage6_masked_forms",
            Self::Blocks => "stage5_blocks",
            Self::TemplateGroups => "stage6_template_groups",
            Self::TemplatedBlocks => "stage7_templated_blocks",
        }
    }
}

#[cfg(feature = "bench_stages")]
impl StageTimes {
    pub fn get(self, stage: Stage) -> u64 {
        self.ns[stage as usize]
    }

    pub fn record(&mut self, stage: Stage, ns: u64) {
        self.ns[stage as usize] += ns;
    }

    pub fn total(self) -> u64 {
        self.ns.iter().sum()
    }

    pub fn since(self, other: Self) -> Self {
        let mut out = self;
        for (slot, base) in out.ns.iter_mut().zip(other.ns) {
            *slot = slot.saturating_sub(base);
        }
        out
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub approx_tokens_in: u64,
    pub approx_tokens_out: u64,
    pub groups_collapsed: u64,
    pub exact_runs: u64,
    pub ws_runs: u64,
    pub block_repeats: u64,
    pub template_groups: u64,
    pub degraded: bool,
    pub noop_reason: Option<NoopReason>,
    pub elapsed_detect_ns: u64,
    pub elapsed_compact_ns: u64,
    pub elapsed_splice_ns: u64,
    pub algo_version: &'static str,
    pub templated_blocks: u64,
    pub options_echo: String,
    pub record_splits: u64,
    pub restore_ids: Vec<String>,
}

impl Stats {
    fn absorb(&mut self, stage: &StageStats) {
        self.groups_collapsed += stage.groups_collapsed;
        self.exact_runs += stage.exact_runs;
        self.ws_runs += stage.ws_runs;
        self.block_repeats += stage.block_repeats;
        self.template_groups += stage.template_groups;
        self.templated_blocks += stage.templated_blocks;
        self.record_splits += stage.record_splits;
    }
}

pub trait Clock {
    fn now_ns(&self) -> u64;
}

pub struct MonotonicClock {
    base: Instant,
}

impl MonotonicClock {
    pub fn new() -> Self {
        Self {
            base: Instant::now(),
        }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MonotonicClock {
    fn now_ns(&self) -> u64 {
        self.base.elapsed().as_nanos() as u64
    }
}

struct Stages {
    ws: wsnorm::Column,
    line: Vec<u8>,
    templ: templ::Scratch,
    blocks: blocks::Scratch,
    templ_blocks: templ_blocks::Scratch,
    #[cfg(feature = "bench_stages")]
    times: StageTimes,
}

impl Stages {
    fn new() -> Self {
        Self {
            ws: wsnorm::Column::default(),
            line: Vec::new(),
            templ: templ::Scratch::default(),
            blocks: blocks::Scratch::new(),
            templ_blocks: templ_blocks::Scratch::new(),
            #[cfg(feature = "bench_stages")]
            times: StageTimes::default(),
        }
    }

    fn reserve(&mut self, span_bytes: usize, units: usize, unit_bytes: usize) {
        if self.ws.reserved().0 < span_bytes || self.ws.reserved().1 < units {
            self.ws = wsnorm::Column::with_capacity(span_bytes, units);
        }
        if self.line.capacity() < unit_bytes {
            self.line = Vec::with_capacity(unit_bytes);
        }
        if self.blocks.reserved() < units {
            self.blocks = blocks::Scratch::with_capacity(units);
        }
        if self.templ.reserved() < unit_bytes {
            self.templ = templ::Scratch::with_capacity(unit_bytes);
        }
        if self.templ_blocks.reserved() < units {
            self.templ_blocks = templ_blocks::Scratch::with_capacity(units);
        }
    }
}

pub struct Compressor {
    clock: Box<dyn Clock>,
    spans: Vec<Span>,
    commits: Vec<Commit>,
    stages: Stages,
    sink: Option<Box<dyn Sink>>,
}

impl Default for Compressor {
    fn default() -> Self {
        Self::new()
    }
}

impl Compressor {
    pub fn new() -> Self {
        Self::with_clock(MonotonicClock::new())
    }

    pub fn with_clock(clock: impl Clock + 'static) -> Self {
        Self {
            clock: Box::new(clock),
            spans: Vec::new(),
            commits: Vec::new(),
            stages: Stages::new(),
            sink: None,
        }
    }

    #[cfg(feature = "bench_stages")]
    pub fn last_stage_times(&self) -> StageTimes {
        self.stages.times
    }

    #[cfg(feature = "bench_stages")]
    pub fn reset_stage_times(&mut self) {
        self.stages.times = StageTimes::default();
    }

    #[cfg(feature = "bench_stages")]
    pub fn compact_span_only(&mut self, span: &[u8], options: &ResolvedOptions) -> StageTimes {
        let before = self.stages.times;
        let style = resolve_style(options.marker_style, span);
        let range = 0..span.len();
        self.commits.clear();
        let _ = compact_span(
            span,
            &range,
            style,
            options,
            &mut self.stages,
            &mut self.commits,
            &*self.clock,
        );
        self.stages.times.since(before)
    }

    pub fn set_sink(&mut self, sink: Box<dyn Sink>) {
        self.sink = Some(sink);
    }

    pub fn commits(&self) -> &[Commit] {
        &self.commits
    }

    pub fn compress(
        &mut self,
        payload: &[u8],
        options: &ResolvedOptions,
        out: &mut Vec<u8>,
    ) -> Stats {
        self.run(payload, None, options, out)
    }

    pub fn compress_as(
        &mut self,
        payload: &[u8],
        schema: Schema,
        options: &ResolvedOptions,
        out: &mut Vec<u8>,
    ) -> Stats {
        self.run(payload, Some(schema), options, out)
    }

    fn run(
        &mut self,
        payload: &[u8],
        pinned: Option<Schema>,
        options: &ResolvedOptions,
        out: &mut Vec<u8>,
    ) -> Stats {
        let Compressor {
            clock,
            spans,
            commits,
            stages,
            sink,
        } = self;
        let detect_start = clock.now_ns();
        let noop = match pinned.or_else(|| sniff::sniff(payload)) {
            None => {
                spans.clear();
                Some(NoopReason::UnknownSchema)
            }
            Some(schema) => locate_into(payload, schema, options.scope_policy, spans),
        };
        let detect_end = clock.now_ns();
        commits.clear();
        let mut stage = StageStats::default();
        let mut degraded = noop.is_some();
        if noop.is_none() {
            for span in spans.iter() {
                let range = span.start..span.end;
                let style = resolve_style(options.marker_style, &payload[range.clone()]);
                let before = commits.len();
                let result = compact_span(
                    payload,
                    &range,
                    style,
                    options,
                    stages,
                    commits,
                    #[cfg(feature = "bench_stages")]
                    &**clock,
                );
                if result.degraded {
                    degraded = true;
                    commits.truncate(before);
                } else {
                    stage.merge(&result.stats);
                }
            }
        }
        let compact_end = clock.now_ns();
        debug_assert!(
            commits
                .windows(2)
                .all(|pair| pair[0].removed.end <= pair[1].removed.start),
            "spans and commits are ascending and disjoint"
        );
        splice_into(payload, commits, out);
        let splice_end = clock.now_ns();
        let mut stats = Stats {
            bytes_in: payload.len() as u64,
            bytes_out: out.len() as u64,
            approx_tokens_in: (payload.len() / 4) as u64,
            approx_tokens_out: (out.len() / 4) as u64,
            degraded,
            noop_reason: noop,
            elapsed_detect_ns: detect_end.saturating_sub(detect_start),
            elapsed_compact_ns: compact_end.saturating_sub(detect_end),
            elapsed_splice_ns: splice_end.saturating_sub(compact_end),
            algo_version: ALGO_VERSION,
            options_echo: options.options_echo(),
            ..Stats::default()
        };
        stats.absorb(&stage);
        if options.reversible {
            stats.restore_ids = reversals(payload, commits, sink);
        }
        stats
    }
}

fn reversals(payload: &[u8], commits: &[Commit], sink: &mut Option<Box<dyn Sink>>) -> Vec<String> {
    let Some(sink) = sink.as_deref_mut() else {
        return Vec::new();
    };
    let mut ids = Vec::with_capacity(commits.len());
    for commit in commits {
        let anchor = &payload[commit.anchor.clone()];
        let mut marker = Vec::new();
        render::render_into(&mut marker, commit.style, commit.kind, commit.count, anchor);
        let original = &payload[commit.removed.clone()];
        let checksum = render::checksum_hex(marker_checksum(anchor));
        if let Some(id) = sink.store(original, &marker, checksum) {
            ids.push(id.to_string());
        }
    }
    ids
}

struct SpanResult {
    stats: StageStats,
    degraded: bool,
}

fn compact_span(
    payload: &[u8],
    range: &Range<usize>,
    style: MarkerStyle,
    options: &ResolvedOptions,
    stages: &mut Stages,
    merged: &mut Vec<Commit>,
    #[cfg(feature = "bench_stages")] clock: &dyn Clock,
) -> SpanResult {
    let bytes = &payload[range.clone()];
    #[cfg(feature = "bench_stages")]
    let mark = clock.now_ns();
    let split = stage1::split_span_counted(bytes, style);
    #[cfg(feature = "bench_stages")]
    record(stages, clock, Stage::Split, mark);
    let units = split.units;
    let longest = units
        .iter()
        .map(|unit| unit.range.len())
        .max()
        .unwrap_or_default();
    stages.reserve(bytes.len(), units.len(), longest);
    let mut ledger = Ledger::new(&units, style);
    let mut stats = StageStats {
        record_splits: split.record_splits as u64,
        ..StageStats::default()
    };
    #[cfg(feature = "bench_stages")]
    let mark = clock.now_ns();
    stages.ws.build(bytes, &units, &mut stages.line);
    #[cfg(feature = "bench_stages")]
    record(stages, clock, Stage::WsColumn, mark);
    #[cfg(feature = "bench_stages")]
    let mark = clock.now_ns();
    stats.merge(&exact::exact_runs(
        bytes,
        &mut ledger,
        options.min_group_size,
    ));
    #[cfg(feature = "bench_stages")]
    record(stages, clock, Stage::ExactRuns, mark);
    if options.normalize_ws {
        #[cfg(feature = "bench_stages")]
        let mark = clock.now_ns();
        stats.merge(&wsruns::ws_runs(
            &stages.ws,
            &mut ledger,
            options.min_group_size,
        ));
        #[cfg(feature = "bench_stages")]
        record(stages, clock, Stage::WsRuns, mark);
    }
    #[cfg(feature = "bench_stages")]
    let mark = clock.now_ns();
    let forms = templ::Forms::build(&stages.ws, &units, &mut stages.templ);
    #[cfg(feature = "bench_stages")]
    record(stages, clock, Stage::MaskedForms, mark);
    #[cfg(feature = "bench_stages")]
    let mark = clock.now_ns();
    stats.merge(&blocks::repeated_blocks(
        &stages.ws,
        forms.as_ref(),
        &mut ledger,
        MIN_BLOCK_LINES,
        MAX_BLOCK_LINES,
        &mut stages.blocks,
    ));
    #[cfg(feature = "bench_stages")]
    record(stages, clock, Stage::Blocks, mark);
    let mut degraded = stages.blocks.degraded();
    if options.template_dedup
        && let Some(forms) = &forms
    {
        #[cfg(feature = "bench_stages")]
        let mark = clock.now_ns();
        stats.merge(&templ::template_groups(
            forms,
            &mut ledger,
            options.min_group_size,
        ));
        #[cfg(feature = "bench_stages")]
        record(stages, clock, Stage::TemplateGroups, mark);
        #[cfg(feature = "bench_stages")]
        let mark = clock.now_ns();
        stats.merge(&templ_blocks::templated_blocks(
            Some(forms),
            &mut ledger,
            MAX_BLOCK_LINES,
            &mut stages.templ_blocks,
        ));
        #[cfg(feature = "bench_stages")]
        record(stages, clock, Stage::TemplatedBlocks, mark);
    }
    degraded |= forms.is_none();
    merged.extend(
        ledger
            .commits()
            .iter()
            .map(|commit| shift(commit, range.start)),
    );
    SpanResult { stats, degraded }
}

#[cfg(feature = "bench_stages")]
fn record(stages: &mut Stages, clock: &dyn Clock, stage: Stage, start: u64) {
    let ns = clock.now_ns().saturating_sub(start);
    stages.times.record(stage, ns);
}

fn shift(commit: &Commit, base: usize) -> Commit {
    Commit {
        kind: commit.kind,
        style: commit.style,
        first: commit.first,
        last: commit.last,
        count: commit.count,
        anchor: commit.anchor.start + base..commit.anchor.end + base,
        removed: commit.removed.start + base..commit.removed.end + base,
    }
}
