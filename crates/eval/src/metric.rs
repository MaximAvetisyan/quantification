use quantification_core::config::{RawOptions, ResolvedOptions, resolve};
use quantification_core::pipeline::{Compressor, Stats};
use quantification_core::sniff::Schema;

use crate::corpus::{Payload, Stratum};
use crate::tokens::{Baseline, Counter};

pub const MEDIAN_TARGET_PERMILLE: u16 = 400;
pub const TARGET_LABEL: &str = ">= 40% median token reduction (provisional, DESIGN.md 12)";

pub struct Measurement {
    pub name: String,
    pub stratum: Stratum,
    pub schema: Option<Schema>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub stats: Stats,
    pub counts: Vec<Option<Count>>,
}

impl Measurement {
    pub fn count(&self, baseline: Baseline) -> Option<Count> {
        self.counts
            .iter()
            .flatten()
            .find(|count| count.baseline == baseline)
            .copied()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Count {
    pub baseline: Baseline,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub reduction_permille: u16,
}

pub struct Summary {
    pub baseline: Baseline,
    pub stratum: Stratum,
    pub cases: usize,
    pub median_permille: u16,
    pub min_permille: u16,
    pub max_permille: u16,
    pub meets_target: bool,
}

pub struct Eval {
    pub options: ResolvedOptions,
    pub baselines: Vec<Baseline>,
    pub measurements: Vec<Measurement>,
    pub unavailable: Vec<(Baseline, String)>,
}

pub fn options() -> ResolvedOptions {
    resolve(&RawOptions::default()).expect("the default options resolve")
}

pub fn measure(payloads: &[Payload], counters: &[Counter], options: &ResolvedOptions) -> Eval {
    let mut compressor = Compressor::new();
    let mut out = Vec::new();
    let unavailable = Vec::new();
    let measurements = payloads
        .iter()
        .map(|payload| {
            let stats = compressor.compress(&payload.bytes, options, &mut out);
            let counts = counters
                .iter()
                .map(|counter| count(counter.baseline(), counter, &payload.bytes, &out))
                .collect();
            Measurement {
                name: payload.name.clone(),
                stratum: payload.stratum,
                schema: payload.schema(),
                bytes_in: payload.bytes.len() as u64,
                bytes_out: stats.bytes_out,
                stats,
                counts,
            }
        })
        .collect();
    Eval {
        options: *options,
        baselines: counters.iter().map(|c| c.baseline()).collect(),
        measurements,
        unavailable,
    }
}

fn count(baseline: Baseline, counter: &Counter, input: &[u8], output: &[u8]) -> Option<Count> {
    let tokens_in = counter.count(input)?.tokens;
    let tokens_out = counter.count(output)?.tokens;
    Some(Count {
        baseline,
        tokens_in,
        tokens_out,
        reduction_permille: permille(tokens_in, tokens_out),
    })
}

pub fn permille(before: u64, after: u64) -> u16 {
    if before == 0 {
        return 0;
    }
    (before.saturating_sub(after).saturating_mul(1000) / before) as u16
}

pub fn percent(permille: u16) -> String {
    format!("{}.{}%", permille / 10, permille % 10)
}

pub fn median(values: &mut [u16]) -> u16 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    let last = values.len() - 1;
    if last.is_multiple_of(2) {
        values[last / 2]
    } else {
        (values[last / 2] + values[last / 2 + 1]) / 2
    }
}

pub fn summarize(eval: &Eval, baseline: Baseline, stratum: Stratum) -> Option<Summary> {
    let mut values: Vec<u16> = eval
        .measurements
        .iter()
        .filter(|m| m.stratum == stratum)
        .filter_map(|m| m.count(baseline))
        .map(|count| count.reduction_permille)
        .collect();
    if values.is_empty() {
        return None;
    }
    let min = *values.iter().min().expect("a non-empty set");
    let max = *values.iter().max().expect("a non-empty set");
    let cases = values.len();
    let median_permille = median(&mut values);
    Some(Summary {
        baseline,
        stratum,
        cases,
        median_permille,
        min_permille: min,
        max_permille: max,
        meets_target: median_permille >= MEDIAN_TARGET_PERMILLE,
    })
}

pub fn summaries(eval: &Eval) -> Vec<Summary> {
    let mut out = Vec::new();
    for baseline in Baseline::ALL {
        for stratum in Stratum::ALL {
            if let Some(summary) = summarize(eval, baseline, stratum) {
                out.push(summary);
            }
        }
    }
    out
}

pub fn compressors_touched(m: &Measurement) -> u64 {
    m.stats.exact_runs
        + m.stats.ws_runs
        + m.stats.block_repeats
        + m.stats.template_groups
        + m.stats.templated_blocks
}
