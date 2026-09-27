use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::metric::{Eval, MEDIAN_TARGET_PERMILLE, TARGET_LABEL, percent, summaries};
use crate::tasks::{PROVIDERS, TaskClass};

pub const NON_BLOCKING: &str = "REPORTING-ONLY: non-blocking until the reference corpus (DESIGN.md 13.4) \
and the task suite (13.5) are ratified; this report never fails a build on its own";

pub fn token_report(eval: &Eval) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "quantification W4.6 token-reduction harness (DESIGN.md 12, success metric)"
    );
    let _ = writeln!(out, "status: {NON_BLOCKING}");
    let _ = writeln!(out, "options: {}", eval.options.options_echo());
    let _ = writeln!(
        out,
        "corpus: {} payloads ({} log_heavy, {} golden, {} adversarial); the reference \
         corpus is unratified (DESIGN.md 13.4), so the population is this harness's own",
        eval.measurements.len(),
        count_of(eval, crate::corpus::Stratum::LogHeavy),
        count_of(eval, crate::corpus::Stratum::Golden),
        count_of(eval, crate::corpus::Stratum::Adversarial),
    );
    for (baseline, reason) in &eval.unavailable {
        let _ = writeln!(out, "tokenizer {} UNAVAILABLE: {reason}", baseline.as_str());
    }
    if !eval.baselines.iter().any(|baseline| {
        baseline.real()
            && eval
                .measurements
                .iter()
                .any(|m| m.count(*baseline).is_some())
    }) {
        let _ = writeln!(
            out,
            "TOKEN REDUCTION: NOT MEASURED: no real tokenizer baseline produced a token count, so \
             the DESIGN.md 12 success metric has no value; bytes/4 does not substitute for it"
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| tokenizer baseline | kind | corpus | payloads | median | min | max | {} | verdict |",
        TARGET_LABEL
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|---|---|---|");
    for summary in summaries(eval) {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | {} | >= {}% | {} |",
            summary.baseline.as_str(),
            if summary.baseline.real() {
                "real"
            } else {
                "PROXY"
            },
            summary.stratum.as_str(),
            summary.cases,
            percent(summary.median_permille),
            percent(summary.min_permille),
            percent(summary.max_permille),
            MEDIAN_TARGET_PERMILLE / 10,
            if !summary.baseline.real() {
                "NOT A SECTION 12 MEASUREMENT"
            } else if summary.meets_target {
                "meets the provisional target"
            } else {
                "BELOW the provisional target"
            }
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "per-schema median, real tokenizers:");
    for baseline in eval.baselines.iter().copied().filter(|b| b.real()) {
        for schema in [
            Some(quantification_core::sniff::Schema::Chat),
            Some(quantification_core::sniff::Schema::Responses),
            Some(quantification_core::sniff::Schema::Messages),
            Some(quantification_core::sniff::Schema::Text),
            None,
        ] {
            let mut values: Vec<u16> = eval
                .measurements
                .iter()
                .filter(|m| m.stratum == crate::corpus::Stratum::LogHeavy)
                .filter(|m| m.schema == schema)
                .filter_map(|m| m.count(baseline))
                .map(|count| count.reduction_permille)
                .collect();
            if values.is_empty() {
                continue;
            }
            let name = schema.map_or("unknown", |s| s.as_str());
            let _ = writeln!(
                out,
                "  {name:>9} / {:<9} n={} median {}",
                baseline.as_str(),
                values.len(),
                percent(crate::metric::median(&mut values))
            );
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| payload | schema | bytes in | bytes out | bytes | exact | ws-runs | blocks | templates | templ-blocks | rec-splits | degraded | noop |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|---|---|---|---|---|---|---|");
    for m in &eval.measurements {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            m.name,
            m.schema.map_or("unknown", |s| s.as_str()),
            m.bytes_in,
            m.bytes_out,
            percent(crate::metric::permille(m.bytes_in, m.bytes_out)),
            m.stats.exact_runs,
            m.stats.ws_runs,
            m.stats.block_repeats,
            m.stats.template_groups,
            m.stats.templated_blocks,
            m.stats.record_splits,
            m.stats.degraded,
            m.stats.noop_reason.map_or("-", |r| r.as_str()),
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "per-payload real-tokenizer counts:");
    for baseline in eval.baselines.iter().copied().filter(|b| b.real()) {
        let _ = writeln!(
            out,
            "  {}: | payload | tokens in | tokens out | reduction |",
            baseline.as_str()
        );
        for m in &eval.measurements {
            let Some(count) = m.count(baseline) else {
                let _ = writeln!(
                    out,
                    "  | {} | not encodable by this tokenizer | | |",
                    m.name
                );
                continue;
            };
            let _ = writeln!(
                out,
                "  | {} | {} | {} | {} |",
                m.name,
                count.tokens_in,
                count.tokens_out,
                percent(count.reduction_permille)
            );
        }
    }
    out
}

fn count_of(eval: &Eval, stratum: crate::corpus::Stratum) -> usize {
    eval.measurements
        .iter()
        .filter(|m| m.stratum == stratum)
        .count()
}

pub fn task_report(measured: bool, reason: &str, scores: &[crate::tasks::ModelScore]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "quantification W4.6 task-quality eval (DESIGN.md 12, utility retention)"
    );
    let _ = writeln!(out, "status: {NON_BLOCKING}");
    let _ = writeln!(
        out,
        "task classes: {}; DESIGN.md 12 requires at least two provider models",
        TaskClass::ALL
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    for class in TaskClass::ALL {
        let _ = writeln!(
            out,
            "  {}: agreement {:?}, {}",
            class.as_str(),
            class.agreement(),
            class.gate_label()
        );
    }
    let _ = writeln!(
        out,
        "scoring: an answer covers a task when every ground-truth fact of that task appears in \
         it; parity needs the baseline answer and the compressed answer to agree, which for the \
         exact classes means the same normalised value and for the fact classes the same fact set"
    );
    for spec in PROVIDERS {
        let _ = writeln!(
            out,
            "provider {} model {} endpoint {} key env {}",
            spec.id, spec.model, spec.endpoint, spec.key_env
        );
    }
    if !measured {
        let _ = writeln!(out, "status: NOT MEASURED: {reason}");
        let _ = writeln!(
            out,
            "no model was called; the parity gates above are unmeasured, not passed and not failed"
        );
        return out;
    }
    for score in scores {
        let _ = writeln!(
            out,
            "model {}/{}: median parity {} across classes",
            score.spec.id,
            score.spec.model,
            percent(score.overall_permille())
        );
        out.push_str(&crate::tasks::task_table(score));
    }
    out
}

pub fn token_json(eval: &Eval) -> String {
    let mut json = String::from("{\n");
    let _ = writeln!(json, "  \"harness\": \"w4.6-token-reduction\",");
    let _ = writeln!(json, "  \"blocking\": false,");
    let _ = writeln!(
        json,
        "  \"non_blocking_reason\": \"DESIGN.md 12: tracked in CI reports until the reference corpus (13.4) is ratified\","
    );
    let _ = writeln!(json, "  \"target_permille\": {MEDIAN_TARGET_PERMILLE},");
    let _ = writeln!(json, "  \"options\": {},", eval.options.options_echo());
    let unavailable: Vec<String> = eval
        .unavailable
        .iter()
        .map(|(b, r)| {
            format!(
                "{{\"baseline\":\"{}\",\"reason\":{}}}",
                b.as_str(),
                quote(r)
            )
        })
        .collect();
    let _ = writeln!(json, "  \"unavailable\": [{}],", unavailable.join(","));
    let _ = writeln!(json, "  \"summaries\": [");
    let summaries = summaries(eval);
    for (at, s) in summaries.iter().enumerate() {
        let _ = writeln!(
            json,
            "    {{\"baseline\":\"{}\",\"real\":{},\"corpus\":\"{}\",\"payloads\":{},\"median_permille\":{},\"min_permille\":{},\"max_permille\":{},\"meets_target\":{}}}{}",
            s.baseline.as_str(),
            s.baseline.real(),
            s.stratum.as_str(),
            s.cases,
            s.median_permille,
            s.min_permille,
            s.max_permille,
            s.baseline.real() && s.meets_target,
            if at + 1 == summaries.len() { "" } else { "," }
        );
    }
    let _ = writeln!(json, "  ],");
    let _ = writeln!(json, "  \"payloads\": [");
    for (at, m) in eval.measurements.iter().enumerate() {
        let counts: Vec<String> = m
            .counts
            .iter()
            .flatten()
            .map(|c| {
                format!(
                    "{{\"baseline\":\"{}\",\"real\":{},\"tokens_in\":{},\"tokens_out\":{},\"reduction_permille\":{}}}",
                    c.baseline.as_str(),
                    c.baseline.real(),
                    c.tokens_in,
                    c.tokens_out,
                    c.reduction_permille
                )
            })
            .collect();
        let _ = writeln!(
            json,
            "    {{\"name\":{},\"stratum\":\"{}\",\"schema\":{},\"bytes_in\":{},\"bytes_out\":{},\"detectors\":{{\"exact_runs\":{},\"ws_runs\":{},\"block_repeats\":{},\"template_groups\":{},\"templated_blocks\":{},\"record_splits\":{}}},\"degraded\":{},\"tokens\":[{}]}}{}",
            quote(m.name.as_str()),
            m.stratum.as_str(),
            quote(m.schema.map_or("unknown", |s| s.as_str())),
            m.bytes_in,
            m.bytes_out,
            m.stats.exact_runs,
            m.stats.ws_runs,
            m.stats.block_repeats,
            m.stats.template_groups,
            m.stats.templated_blocks,
            m.stats.record_splits,
            m.stats.degraded,
            counts.join(","),
            if at + 1 == eval.measurements.len() {
                ""
            } else {
                ","
            }
        );
    }
    json.push_str("  ]\n}\n");
    json
}

pub fn task_json(measured: bool, reason: &str, scores: &[crate::tasks::ModelScore]) -> String {
    let mut json = String::from("{\n");
    let _ = writeln!(json, "  \"harness\": \"w4.6-task-quality\",");
    let _ = writeln!(json, "  \"blocking\": false,");
    let _ = writeln!(
        json,
        "  \"non_blocking_reason\": \"DESIGN.md 12: provisional, non-blocking until the task suite (13.5) is ratified\","
    );
    let _ = writeln!(json, "  \"measured\": {measured},");
    let _ = writeln!(json, "  \"status\": {},", quote(reason));
    let _ = writeln!(
        json,
        "  \"providers\": [{}],",
        PROVIDERS
            .iter()
            .map(|p| {
                format!(
                    "{{\"id\":\"{}\",\"model\":\"{}\",\"endpoint\":\"{}\",\"key_env\":\"{}\"}}",
                    p.id, p.model, p.endpoint, p.key_env
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    );
    let classes: Vec<String> = TaskClass::ALL
        .iter()
        .map(|c| {
            format!(
                "{{\"class\":\"{}\",\"agreement\":\"{:?}\",\"threshold_permille\":{}}}",
                c.as_str(),
                c.agreement(),
                c.threshold_permille()
            )
        })
        .collect();
    let _ = writeln!(json, "  \"classes\": [{}],", classes.join(","));
    let models: Vec<String> = scores
        .iter()
        .map(|s| {
            let classes: Vec<String> = s
                .classes
                .iter()
                .map(|c| {
                    format!(
                        "{{\"class\":\"{}\",\"scored\":{},\"not_scored\":{},\"parity_permille\":{},\"threshold_permille\":{},\"meets_gate\":{}}}",
                        c.class.as_str(),
                        c.scored,
                        c.not_scored,
                        c.parity_permille,
                        c.threshold_permille,
                        c.meets_gate
                    )
                })
                .collect();
            format!(
                "{{\"id\":\"{}\",\"model\":\"{}\",\"overall_permille\":{},\"classes\":[{}]}}",
                s.spec.id,
                s.spec.model,
                s.overall_permille(),
                classes.join(",")
            )
        })
        .collect();
    let _ = writeln!(json, "  \"models\": [{}]", models.join(","));
    json.push_str("}\n");
    json
}

pub fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn write_report(relative: &str, body: &str) -> PathBuf {
    let given = Path::new(relative);
    let path = if given.is_absolute() {
        given.to_path_buf()
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&path, body).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    path
}
