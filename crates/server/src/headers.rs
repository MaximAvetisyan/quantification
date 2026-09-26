use axum::http::{HeaderMap, HeaderName, HeaderValue};

use quantification_core::api::Stats;

pub fn pairs(stats: &Stats) -> Vec<(&'static str, String)> {
    let mut pairs = vec![
        ("x-stats-bytes-in", stats.bytes_in.to_string()),
        ("x-stats-bytes-out", stats.bytes_out.to_string()),
        (
            "x-stats-approx-tokens-in",
            stats.approx_tokens_in.to_string(),
        ),
        (
            "x-stats-approx-tokens-out",
            stats.approx_tokens_out.to_string(),
        ),
        (
            "x-stats-groups-collapsed",
            stats.groups_collapsed.to_string(),
        ),
        ("x-stats-exact-runs", stats.exact_runs.to_string()),
        ("x-stats-ws-runs", stats.ws_runs.to_string()),
        ("x-stats-block-repeats", stats.block_repeats.to_string()),
        ("x-stats-template-groups", stats.template_groups.to_string()),
        (
            "x-stats-templated-blocks",
            stats.templated_blocks.to_string(),
        ),
        ("x-stats-record-splits", stats.record_splits.to_string()),
        ("x-stats-degraded", stats.degraded.to_string()),
    ];
    if let Some(reason) = stats.noop_reason {
        pairs.push(("x-stats-noop-reason", reason.as_str().to_string()));
    }
    pairs.push(("x-stats-algo-version", stats.algo_version.to_string()));
    pairs
}

pub fn apply(out: &mut HeaderMap, stats: &Stats) {
    for (name, value) in pairs(stats) {
        out.insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(&value).expect("stats values are ascii"),
        );
    }
}
