use std::ops::Range;
use std::time::Instant;

use crate::config::{MAX_BLOCK_LINES, MIN_BLOCK_LINES, MarkerStyle, ResolvedOptions};
use crate::detect::{blocks, exact, templ, templ_blocks, wsruns};
use crate::ledger::{Commit, Ledger, StageStats};
use crate::locator::{NoopReason, Span, locate_into};
use crate::render::resolve_style;
use crate::sniff;
use crate::splice::splice_into;
use crate::stage1;

pub const ALGO_VERSION: &str = "0.1.0";

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
    ws: wsruns::Scratch,
    templ: templ::Scratch,
    blocks: blocks::Scratch,
    templ_blocks: templ_blocks::Scratch,
}

impl Stages {
    fn new() -> Self {
        Self {
            ws: wsruns::Scratch::default(),
            templ: templ::Scratch::default(),
            blocks: blocks::Scratch::new(),
            templ_blocks: templ_blocks::Scratch::new(),
        }
    }

    fn reserve(&mut self, span_bytes: usize, units: usize, unit_bytes: usize) {
        if self.blocks.reserved().0 < span_bytes || self.blocks.reserved().1 < unit_bytes {
            self.blocks = blocks::Scratch::with_capacity(span_bytes, unit_bytes);
        }
        if self.ws.reserved().0 < unit_bytes {
            self.ws = wsruns::Scratch::with_capacity(unit_bytes, unit_bytes);
        }
        if self.templ.reserved().0 < unit_bytes {
            self.templ = templ::Scratch::with_capacity(unit_bytes, unit_bytes);
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
        }
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
        let Compressor {
            clock,
            spans,
            commits,
            stages,
        } = self;
        let detect_start = clock.now_ns();
        let noop = match sniff::sniff(payload) {
            None => Some(NoopReason::UnknownSchema),
            Some(schema) => locate_into(payload, schema, options.scope_policy, spans),
        };
        let detect_end = clock.now_ns();
        commits.clear();
        let mut stage = StageStats::default();
        let mut degraded = noop.is_some();
        let mut style = resolve_style(options.marker_style, payload);
        let mut agreed: Option<MarkerStyle> = None;
        let mut unanimous = true;
        if noop.is_none() {
            for span in spans.iter() {
                let range = span.start..span.end;
                let resolved = resolve_style(options.marker_style, &payload[range.clone()]);
                if let Some(first) = agreed {
                    unanimous &= first == resolved;
                } else {
                    agreed = Some(resolved);
                }
                let before = commits.len();
                let result = compact_span(payload, &range, resolved, options, stages, commits);
                if result.degraded {
                    degraded = true;
                    commits.truncate(before);
                } else {
                    stage.merge(&result.stats);
                }
            }
            if unanimous {
                style = agreed.unwrap_or(style);
            }
        }
        let compact_end = clock.now_ns();
        debug_assert!(
            commits
                .windows(2)
                .all(|pair| pair[0].removed.end <= pair[1].removed.start),
            "spans and commits are ascending and disjoint"
        );
        splice_into(payload, style, commits, out);
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
        stats
    }
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
) -> SpanResult {
    let bytes = &payload[range.clone()];
    let split = stage1::split_span_counted(bytes);
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
    stats.merge(&exact::exact_runs(
        bytes,
        &mut ledger,
        options.min_group_size,
    ));
    if options.normalize_ws {
        stats.merge(&wsruns::ws_runs(
            bytes,
            &mut ledger,
            options.min_group_size,
            &mut stages.ws,
        ));
    }
    stats.merge(&blocks::repeated_blocks(
        bytes,
        &mut ledger,
        MIN_BLOCK_LINES,
        MAX_BLOCK_LINES,
        &mut stages.blocks,
    ));
    let mut degraded = stages.blocks.degraded();
    if options.template_dedup {
        let templated = templ::template_groups(
            bytes,
            &mut ledger,
            options.min_group_size,
            &mut stages.templ,
        );
        stats.merge(&templated.stats);
        stats.merge(&templ_blocks::templated_blocks(
            &templated,
            &mut ledger,
            MAX_BLOCK_LINES,
            &mut stages.templ_blocks,
        ));
        degraded |= templated.degraded;
    }
    merged.extend(
        ledger
            .commits()
            .iter()
            .map(|commit| shift(commit, range.start)),
    );
    SpanResult { stats, degraded }
}

fn shift(commit: &Commit, base: usize) -> Commit {
    Commit {
        kind: commit.kind,
        first: commit.first,
        last: commit.last,
        count: commit.count,
        anchor: commit.anchor.start + base..commit.anchor.end + base,
        removed: commit.removed.start + base..commit.removed.end + base,
    }
}
