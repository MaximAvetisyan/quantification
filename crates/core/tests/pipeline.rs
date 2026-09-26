use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;

use quantification_core::config::{
    MarkerStyle, RawOptions, ResolveError, ResolvedOptions, ScopePolicy, resolve,
};
use quantification_core::fingerprint::marker_checksum;
use quantification_core::ledger::{Commit, CommitKind, framing};
use quantification_core::pipeline::{ALGO_VERSION, Clock, Compressor, MonotonicClock, Stats};

const CHAT_CORPUS: &[&str] = &[
    "schemas/chat-minified.json",
    "schemas/chat-pretty.json",
    "shapes/chat-content-null.json",
    "shapes/chat-mixed-parts.json",
    "shapes/sniff-overlap-chat-responses.json",
    "edges/bom-chat.json",
    "edges/dup-keys-last-wins.json",
    "edges/escaped-structural-keys.json",
    "edges/newlines-u000a-only.json",
    "edges/prior-markers.json",
    "edges/profitability-below-threshold.json",
    "edges/single-line-tool-dump-small.json",
];

const CORPUS: &[&str] = &[
    "schemas/chat-minified.json",
    "schemas/chat-pretty.json",
    "schemas/messages-minified.json",
    "schemas/messages-pretty.json",
    "schemas/responses-minified.json",
    "schemas/responses-pretty.json",
    "schemas/text-plain.txt",
    "shapes/anthropic-system-top.json",
    "shapes/anthropic-tool-result.json",
    "shapes/chat-content-null.json",
    "shapes/chat-mixed-parts.json",
    "shapes/responses-function-call-output.json",
    "shapes/responses-input-string.json",
    "shapes/sniff-overlap-chat-responses.json",
    "edges/bom-chat.json",
    "edges/dup-keys-last-wins.json",
    "edges/escaped-structural-keys.json",
    "edges/newlines-u000a-only.json",
    "edges/prior-markers.json",
    "edges/profitability-below-threshold.json",
    "edges/single-line-tool-dump-overcap.json",
    "edges/single-line-tool-dump-small.json",
    "edges/stage1b-no-separator-overcap.json",
    "edges/stage1b-record-len-16383.json",
    "edges/stage1b-record-len-16384.json",
    "edges/stage1b-record-len-16385.json",
];

const CHILD_BYTES_ENV: &str = "QUANT_M2_CHILD_BYTES";
const CHILD_TEST: &str = "m2_child_writes_the_corpus_outputs";

fn root(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

fn fixture(rel: &str) -> Vec<u8> {
    let path = root(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn golden_rel(name: &str) -> String {
    let base = name.rsplit('/').next().expect("fixture name");
    format!("golden/{}", base)
}

fn golden(name: &str) -> Vec<u8> {
    let path = root(&golden_rel(name));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn options(raw: &RawOptions) -> ResolvedOptions {
    resolve(raw).expect("options resolve")
}

fn defaults() -> ResolvedOptions {
    options(&RawOptions::default())
}

struct Run {
    payload: Vec<u8>,
    stats: Stats,
    commits: Vec<Commit>,
}

fn compress_with(compressor: &mut Compressor, payload: &[u8], opts: &ResolvedOptions) -> Run {
    let mut out = Vec::new();
    let stats = compressor.compress(payload, opts, &mut out);
    Run {
        payload: out,
        stats,
        commits: compressor.commits().to_vec(),
    }
}

fn compress(payload: &[u8], opts: &ResolvedOptions) -> Run {
    compress_with(&mut Compressor::new(), payload, opts)
}

fn chat_corpus() -> Vec<(String, Vec<u8>)> {
    CHAT_CORPUS
        .iter()
        .map(|name| (name.to_string(), fixture(name)))
        .collect()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("pipeline output is valid utf-8")
}

fn doc(messages: &[(&str, &str)]) -> Vec<u8> {
    let mut out = String::from(r#"{"model":"gpt-4o","messages":["#);
    for (at, (role, content)) in messages.iter().enumerate() {
        if at > 0 {
            out.push(',');
        }
        out.push_str(&format!(r#"{{"role":"{role}","content":"{content}"}}"#));
    }
    out.push_str("]}");
    out.into_bytes()
}

fn joined(lines: &[String]) -> String {
    lines.join(r"\n")
}

fn code(mut n: usize) -> String {
    let mut out = Vec::new();
    for _ in 0..5 {
        out.push(b'a' + (n % 26) as u8);
        n /= 26;
    }
    out.reverse();
    String::from_utf8(out).expect("ascii code")
}

fn unique_lines(count: usize) -> Vec<String> {
    (0..count)
        .map(|at| {
            format!(
                "2026-08-25T10:00:00Z unique note {} nothing repeats",
                code(at)
            )
        })
        .collect()
}

const LOG: &str = "2026-08-25T10:00:{ss}Z INFO {tag} 10.0.0.{ip} took {dur} ok";

fn log_burst(count: usize) -> Vec<String> {
    tagged_burst(count, "hc")
}

fn tagged_burst(count: usize, tag: &str) -> Vec<String> {
    (0..count)
        .map(|at| {
            LOG.replace("{ss}", &format!("{at:02}"))
                .replace("{tag}", tag)
                .replace("{ip}", &format!("{}", at % 8 + 1))
                .replace("{dur}", &format!("{}ms", at))
        })
        .collect()
}

// ---------------------------------------------------------------- goldens

#[test]
fn the_chat_goldens_are_reproduced_byte_for_byte() {
    for name in CHAT_CORPUS {
        let run = compress(&fixture(name), &defaults());
        assert_eq!(
            run.payload,
            golden(name),
            "{name} does not reproduce its golden output"
        );
    }
}

#[test]
fn the_chat_goldens_are_not_all_passthroughs() {
    let mut collapsed = 0;
    for name in CHAT_CORPUS {
        let run = compress(&fixture(name), &defaults());
        if run.payload != fixture(name) {
            collapsed += 1;
        }
    }
    assert!(
        collapsed >= 4,
        "only {collapsed} chat fixtures changed; the corpus is not exercising the stages"
    );
}

#[test]
#[ignore = "golden generator: writes tests/fixtures/golden/ from the current implementation"]
fn write_the_chat_goldens() {
    let dir = root("golden");
    std::fs::create_dir_all(&dir).expect("golden dir");
    for name in CHAT_CORPUS {
        let run = compress(&fixture(name), &defaults());
        let path = dir.join(name.rsplit('/').next().expect("fixture name"));
        std::fs::write(&path, &run.payload).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    }
}

#[test]
fn the_pretty_and_minified_chat_variants_compress_the_same_span() {
    let minified = compress(&fixture("schemas/chat-minified.json"), &defaults());
    let pretty = compress(&fixture("schemas/chat-pretty.json"), &defaults());
    assert_eq!(minified.stats.groups_collapsed, 1);
    assert_eq!(pretty.stats.groups_collapsed, 1);
    assert_eq!(minified.stats.template_groups, 1);
    let marker = b"rows, template";
    for (name, run) in [("minified", &minified), ("pretty", &pretty)] {
        assert_eq!(
            run.payload
                .windows(marker.len())
                .filter(|w| *w == marker)
                .count(),
            1,
            "one template marker in the {name} payload"
        );
        assert!(
            !text(&run.payload).contains('\u{27ea}'),
            "a single all-ascii span resolves to the ascii style; the mixed-style case is \
             each_span_renders_in_its_own_resolved_style"
        );
    }
    let anchor = b"2026-08-25T10:00:01Z INFO hc 10.0.0.1 ok";
    assert_eq!(minified.commits[0].anchor.len(), anchor.len());
    assert_eq!(
        &minified.payload[minified.commits[0].removed.start..][..anchor.len()],
        anchor
    );
}

// ---------------------------------------------------------------- degradation

#[test]
fn an_unknown_schema_passes_through_untouched() {
    for payload in [
        br#"{"totally":"other","values":[1,2,3]}"#.to_vec(),
        String::from("[1, 2, 3]").into_bytes(),
        String::from(r#"{"only":"scalars","and":42}"#).into_bytes(),
    ] {
        let run = compress(&payload, &defaults());
        assert_eq!(run.payload, payload);
        assert!(run.stats.degraded);
        assert_eq!(
            run.stats.noop_reason.map(|r| r.as_str()),
            Some("unknown_schema")
        );
        assert_eq!(run.stats.groups_collapsed, 0);
        assert!(run.commits.is_empty());
    }
}

#[test]
fn plain_text_is_the_degenerate_schema_not_a_degrade() {
    let payload = b"not json at all, just text with no braces".to_vec();
    let run = compress(&payload, &defaults());
    assert!(!run.stats.degraded);
    assert_eq!(run.stats.noop_reason, None);
    assert_eq!(run.payload, payload);
}

#[test]
fn degenerate_payloads_never_fail_and_never_change() {
    for payload in [
        Vec::new(),
        vec![b' '; 8],
        b"null".to_vec(),
        b"{}".to_vec(),
        b"[]".to_vec(),
        b"\"a bare json string\"".to_vec(),
    ] {
        let run = compress(&payload, &defaults());
        assert_eq!(run.payload, payload);
        assert_eq!(run.stats.groups_collapsed, 0);
        assert!(run.commits.is_empty());
        assert_eq!(run.stats.bytes_in, payload.len() as u64);
        assert_eq!(run.stats.bytes_out, payload.len() as u64);
    }
}

#[test]
fn a_malformed_document_passes_through_untouched() {
    for payload in [
        br#"{"messages":[{"role":"user","content":"a\nb"},"#.to_vec(),
        br#"{"messages":[{"role":"user" "content":"a"}]}"#.to_vec(),
        br#"{"messages":[{"role":"user","content":"a"}]}{"x":1}"#.to_vec(),
    ] {
        let run = compress(&payload, &defaults());
        assert_eq!(run.payload, payload);
        assert!(run.stats.degraded);
        assert_eq!(run.stats.noop_reason.map(|r| r.as_str()), Some("malformed"));
    }
}

#[test]
fn a_degraded_request_still_reports_its_shape() {
    let payload = br#"{"nope":1}"#.to_vec();
    let run = compress(&payload, &defaults());
    assert_eq!(run.stats.bytes_in, payload.len() as u64);
    assert_eq!(run.stats.bytes_out, payload.len() as u64);
    assert_eq!(run.stats.approx_tokens_in, (payload.len() / 4) as u64);
    assert_eq!(run.stats.approx_tokens_out, run.stats.approx_tokens_in);
    assert_eq!(run.stats.algo_version, ALGO_VERSION);
    assert_eq!(run.stats.options_echo, defaults().options_echo());
}

// ---------------------------------------------------------------- one span, two spans

#[test]
fn one_span_compresses_while_another_in_the_same_payload_does_not() {
    let compressible = joined(&log_burst(6));
    let unique = joined(&unique_lines(6));
    let payload = doc(&[("user", &compressible), ("user", &unique)]);
    let run = compress(&payload, &defaults());
    assert_eq!(run.commits.len(), 1);
    assert!(run.payload.len() < payload.len());
    let commit = &run.commits[0];
    let removed = &payload[commit.removed.clone()];
    assert_eq!(text(removed), compressible);
    assert_eq!(
        &run.payload[..commit.removed.start],
        &payload[..commit.removed.start]
    );
    let tail = &payload[commit.removed.end..];
    assert_eq!(&run.payload[run.payload.len() - tail.len()..], tail);
    assert!(text(&run.payload).contains("rows, template"));
}

#[test]
fn commits_of_every_span_merge_into_one_ascending_list() {
    let first = joined(&log_burst(6));
    let second = joined(&log_burst(6));
    let payload = doc(&[
        ("user", &first),
        ("assistant", "never touched"),
        ("user", &second),
    ]);
    let run = compress(&payload, &defaults());
    assert_eq!(run.commits.len(), 2);
    assert!(run.commits[0].removed.end <= run.commits[1].removed.start);
    let spliced = run.payload.len();
    assert_eq!(spliced, run.stats.bytes_out as usize);
    for commit in &run.commits {
        assert!(commit.removed.end <= payload.len());
        assert_eq!(&run.payload[0..1], &payload[0..1]);
    }
}

#[test]
fn a_span_whose_table_fills_degrades_alone_and_leaves_the_others_compressed() {
    let small = joined(&[
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
    ]);
    let mut flood = vec![
        "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ".to_string(),
        "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ".to_string(),
        "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ".to_string(),
        "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ".to_string(),
    ];
    flood.extend(unique_lines(200_000));
    let flood_span = joined(&flood);
    let payload = doc(&[("user", &small), ("user", &flood_span)]);
    let run = compress(&payload, &defaults());
    assert!(
        run.stats.degraded,
        "the flooding span must degrade the request"
    );
    assert_eq!(run.stats.noop_reason, None, "the request itself was served");
    assert_eq!(run.commits.len(), 1, "only the small span committed");
    let commit = &run.commits[0];
    assert!(
        commit.removed.end < flood_span.len(),
        "the commit is in the first span"
    );
    let small_out = &run.payload[commit.removed.start..commit.removed.start + 200];
    assert_eq!(
        text(small_out)
            .matches("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .count(),
        1,
        "the small span collapsed to its anchor plus a marker"
    );
    assert!(text(small_out).contains("identical"));
    let flood_at = find(&payload, &flood_span.as_bytes()[..64]).expect("flood span");
    let verbatim_tail = &payload[flood_at..];
    assert_eq!(
        &run.payload[run.payload.len() - verbatim_tail.len()..],
        verbatim_tail,
        "the degraded span is copied verbatim"
    );
    assert_eq!(
        text(&run.payload).matches(&"Q".repeat(40)).count(),
        4,
        "the degraded span's own stage-3 run survives verbatim"
    );
}

// ---------------------------------------------------------------- options

#[test]
fn normalize_ws_false_skips_stage_four() {
    let lines = vec![
        "2026-08-25 pad row one of the log stream".to_string(),
        "2026-08-25   pad row one of the log stream".to_string(),
        r"2026-08-25 pad\trow one of the log stream".to_string(),
    ];
    let payload = doc(&[("user", &joined(&lines))]);

    let with = compress(&payload, &defaults());
    assert_eq!(with.stats.ws_runs, 1);
    assert_eq!(with.stats.template_groups, 0);
    assert!(text(&with.payload).contains("rows, ws-equal"));

    let without = compress(
        &payload,
        &options(&RawOptions {
            normalize_ws: Some(false),
            ..RawOptions::default()
        }),
    );
    assert_eq!(without.stats.ws_runs, 0, "stage 4 is skipped entirely");
    assert_eq!(without.stats.template_groups, 1);
    assert!(text(&without.payload).contains("rows, template"));
    assert!(!text(&without.payload).contains("ws-equal"));

    let neither = compress(
        &payload,
        &options(&RawOptions {
            normalize_ws: Some(false),
            template_dedup: Some(false),
            ..RawOptions::default()
        }),
    );
    assert_eq!(neither.payload, payload, "stages 4, 6 and 7 are all off");
}

#[test]
fn template_dedup_false_skips_stages_six_and_seven() {
    let lines = log_burst(6);
    let payload = doc(&[("user", &joined(&lines))]);

    let with = compress(&payload, &defaults());
    assert_eq!(with.stats.template_groups, 1);
    assert_eq!(with.stats.templated_blocks, 0);

    let without = compress(
        &payload,
        &options(&RawOptions {
            template_dedup: Some(false),
            ..RawOptions::default()
        }),
    );
    assert_eq!(without.stats.template_groups, 0);
    assert_eq!(without.stats.templated_blocks, 0);
    assert_eq!(
        without.payload, payload,
        "nothing commits without stages 6 and 7"
    );
}

#[test]
fn template_dedup_false_also_disables_stage_seven() {
    let mut lines = Vec::new();
    for at in 0..3 {
        lines.push(format!(
            "2026-08-25T10:00:0{at}Z GET /a from 10.0.0.1 in 5ms"
        ));
        lines.push(format!(
            "2026-08-25T10:00:0{at}Z <- 200 bytes 900 receipt 00-{at}"
        ));
        lines.push(format!("2026-08-25T10:00:0{at}Z pool 4 idle 0"));
    }
    let payload = doc(&[("user", &joined(&lines))]);

    let with = compress(&payload, &defaults());
    assert_eq!(with.stats.templated_blocks, 1);
    assert!(text(&with.payload).contains("templated block"));

    let without = compress(
        &payload,
        &options(&RawOptions {
            template_dedup: Some(false),
            ..RawOptions::default()
        }),
    );
    assert_eq!(without.stats.templated_blocks, 0);
    assert_eq!(without.stats.template_groups, 0);
    assert_eq!(without.payload, payload);
}

#[test]
fn min_group_size_is_honoured_by_the_run_stages() {
    let line = "a plain repeated log line with no maskable field at all";
    let lines = vec![line.to_string(), line.to_string(), line.to_string()];
    let payload = doc(&[("user", &joined(&lines))]);

    let at_three = compress(
        &payload,
        &options(&RawOptions {
            min_group_size: Some(3),
            ..RawOptions::default()
        }),
    );
    assert_eq!(at_three.stats.exact_runs, 1, "stage 3 claims the run first");
    assert_eq!(at_three.stats.templated_blocks, 0);

    let at_four = compress(
        &payload,
        &options(&RawOptions {
            min_group_size: Some(4),
            ..RawOptions::default()
        }),
    );
    assert_eq!(
        at_four.stats.exact_runs, 0,
        "the run stages honour the floor"
    );
    assert!(!at_four.stats.degraded);
    assert!(at_four.stats.bytes_out <= at_four.stats.bytes_in);
}

#[test]
fn min_group_size_does_not_gate_the_templated_block_stage() {
    let line = "a plain repeated log line with no maskable field at all";
    let lines = vec![line.to_string(), line.to_string(), line.to_string()];
    let payload = doc(&[("user", &joined(&lines))]);
    let at_four = compress(
        &payload,
        &options(&RawOptions {
            min_group_size: Some(4),
            template_dedup: Some(false),
            ..RawOptions::default()
        }),
    );
    assert_eq!(at_four.payload, payload);
    let at_four_with_templates = compress(
        &payload,
        &options(&RawOptions {
            min_group_size: Some(4),
            ..RawOptions::default()
        }),
    );
    assert_eq!(
        at_four_with_templates.stats.templated_blocks, 1,
        "stage 7's minimum is a period, not a group size"
    );
    assert_eq!(at_four_with_templates.stats.exact_runs, 0);
}

#[test]
fn the_scope_policy_decides_which_spans_are_touched() {
    let user = joined(&log_burst(6));
    let tool = joined(&log_burst(6));
    let payload = doc(&[("user", &user), ("tool", &tool)]);

    let users_only = compress(
        &payload,
        &options(&RawOptions {
            scope_policy: Some(ScopePolicy::UserContent),
            ..RawOptions::default()
        }),
    );
    assert_eq!(users_only.commits.len(), 1);
    assert!(users_only.commits[0].removed.end < payload.len() - tool.len());

    let with_tools = compress(
        &payload,
        &options(&RawOptions {
            scope_policy: Some(ScopePolicy::UserAndTools),
            ..RawOptions::default()
        }),
    );
    assert_eq!(with_tools.commits.len(), 2);
    assert!(with_tools.payload.len() < users_only.payload.len());
}

#[test]
fn a_reserved_scope_policy_never_reaches_the_pipeline() {
    let raw = RawOptions {
        scope_policy: Some(ScopePolicy::AllMessages),
        ..RawOptions::default()
    };
    assert!(matches!(
        resolve(&raw),
        Err(ResolveError::UnsupportedScopePolicy(
            ScopePolicy::AllMessages
        ))
    ));
}

// ---------------------------------------------------------------- scoping (R4)

fn doc_with_system(system: &str, messages: &[(&str, &str)]) -> Vec<u8> {
    let mut out = format!(r#"{{"model":"gpt-4o","system":"{system}","messages":["#);
    for (at, (role, content)) in messages.iter().enumerate() {
        if at > 0 {
            out.push(',');
        }
        out.push_str(&format!(r#"{{"role":"{role}","content":"{content}"}}"#));
    }
    out.push_str("]}");
    out.into_bytes()
}

#[test]
fn no_marker_ever_reaches_system_or_assistant_content() {
    let system = joined(&tagged_burst(6, "sys"));
    let assistant = joined(&tagged_burst(6, "asst"));
    let user = joined(&tagged_burst(6, "usr"));
    let payload = doc_with_system(&system, &[("assistant", &assistant), ("user", &user)]);
    let run = compress(&payload, &defaults());
    assert_eq!(run.commits.len(), 1, "only the user span committed");
    let commit = &run.commits[0];
    let system_at = find(&payload, br#""system":""#).expect("system key") + 10;
    let user_at = find(&payload, user.as_bytes()).expect("user content");
    assert_eq!(commit.removed.start, user_at);
    let head = text(&payload[system_at..commit.removed.start]);
    assert_eq!(
        &run.payload[system_at..commit.removed.start],
        head.as_bytes()
    );
    assert!(head.contains(&system));
    assert!(head.contains(&assistant));
    assert!(
        !head.contains("rows,") && !head.contains("identical"),
        "a marker reached system or assistant content"
    );
    let tail = &payload[commit.removed.end..];
    assert_eq!(&run.payload[run.payload.len() - tail.len()..], tail);
}

#[test]
fn the_anthropic_top_level_system_fixture_keeps_its_system_bytes() {
    let payload = fixture("shapes/anthropic-system-top.json");
    let run = compress(&payload, &defaults());
    let system_at = find(&payload, br#""system":""#).expect("system key");
    let content_at = find(&payload, br#""content":""#).expect("content key");
    assert!(
        system_at < content_at,
        "the fixture has a top-level system before the content"
    );
    assert_eq!(
        &run.payload[..content_at],
        &payload[..content_at],
        "everything before the eligible span is bit-identical"
    );
}

// ---------------------------------------------------------------- properties

#[test]
fn recompressing_an_output_is_a_fixed_point() {
    for name in CORPUS {
        let payload = fixture(name);
        let once = compress(&payload, &defaults());
        let twice = compress(&once.payload, &defaults());
        assert_eq!(twice.payload, once.payload, "{name} is not idempotent");
        assert_eq!(twice.stats.groups_collapsed, 0);
        assert!(twice.payload.len() <= once.payload.len());
    }
}

const REPRO: [&str; 6] = [
    "2026-08-25T10:00:01Z INFO hc 10.0.0.1 GET /v1/users?id=1 id=aaaaaaaa-1111-2222-3333-444444444444 took 5ms",
    "2026-08-25T10:00:02Z INFO hc 10.0.0.2 GET /v1/users?id=2 id=bbbbbbbb-1111-2222-3333-444444444444 took 6ms",
    "2026-08-25T10:00:03Z INFO hc 10.0.0.3 <- 200 bytes 4001 status 7ms id=cccccccc-1111-2222-3333-444444444444 took 7ms",
    "2026-08-25T10:00:04Z INFO hc 10.0.0.4 GET /v1/users?id=3 id=dddddddd-1111-2222-3333-444444444444 took 8ms",
    "2026-08-25T10:00:05Z INFO hc 10.0.0.5 GET /v1/users?id=4 id=eeeeeeee-1111-2222-3333-444444444444 took 9ms",
    "2026-08-25T10:00:06Z INFO hc 10.0.0.6 <- 200 bytes 4003 status 7ms id=ffffffff-1111-2222-3333-444444444444 took 10ms",
];

#[test]
fn a_block_whose_anchor_hides_a_shorter_period_is_not_a_fixed_point_of_itself() {
    let payload = doc(&[("user", &joined(&REPRO.map(String::from)))]);
    let once = compress(&payload, &defaults());
    let twice = compress(&once.payload, &defaults());
    assert_eq!(once.commits.len(), 2, "the two hidden pairs, not one block");
    assert!(
        once.commits.iter().all(|commit| {
            commit.kind == CommitKind::TemplatedBlock
                && commit.count == 1
                && commit.removed.len() == 2 * commit.anchor.len() + 2
        }),
        "no commit keeps the three-line anchor that hid the pair: {:?}",
        once.commits
    );
    assert_eq!(twice.payload, once.payload, "the repro is a fixed point");
    assert_eq!(twice.stats.groups_collapsed, 0);
    assert!(once.payload.len() < payload.len());
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const ROLES: [&str; 4] = ["hc", "gateway", "pool", "worker"];
const PADS: [&str; 4] = ["", "  ", "\\t", " \\t "];

fn burst_line(rng: &mut Rng, role: &str, kind: usize, entry: usize) -> String {
    let second = rng.below(60);
    let ip = rng.below(64) + 1;
    let tail = match kind {
        0 => format!("GET /v1/users?id={entry}"),
        1 => format!("<- 200 bytes {} status 7ms", 4000 + entry),
        2 => format!("pool conns {entry} idle 0"),
        _ => format!("boot phase node 10.1.{ip}.{} ok", entry % 256),
    };
    format!(
        "2026-08-25T10:00:{second:02}Z INFO {role} 10.0.0.{ip} {tail} id={entry:08x}-1111-2222-3333-{entry:012x} took {}ms",
        rng.below(900)
    )
}

fn padded(rng: &mut Rng, line: &str) -> String {
    let pad = PADS[rng.below(PADS.len())];
    format!("{pad}{line}{pad}")
}

fn burst_span(rng: &mut Rng) -> String {
    let mut lines: Vec<String> = Vec::new();
    for group in 0..1 + rng.below(4) {
        let role = ROLES[rng.below(ROLES.len())];
        let header = burst_line(rng, role, 3, group);
        lines.push(padded(rng, &header));
        let pattern: Vec<usize> = (0..1 + rng.below(3)).map(|_| rng.below(2)).collect();
        for entry in 0..2 + rng.below(3) {
            for kind in &pattern {
                let fresh = burst_line(rng, role, *kind, group * 7 + entry);
                lines.push(padded(rng, &fresh));
            }
        }
        if rng.below(4) == 0 {
            let repeated = lines.clone();
            for (offset, previous) in repeated.iter().enumerate() {
                if offset % 3 == 0 {
                    lines.push(previous.clone());
                } else {
                    let fresh = burst_line(rng, role, offset % 2, group + offset);
                    lines.push(padded(rng, &fresh));
                }
            }
        }
    }
    joined(&lines)
}

const GENERATED_BURSTS: usize = 2000;

fn generated_payloads(count: usize) -> Vec<Vec<u8>> {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    (0..count)
        .map(|_| {
            let spans: Vec<String> = (0..1 + rng.below(2))
                .map(|_| burst_span(&mut rng))
                .collect();
            let borrowed: Vec<(&str, &str)> =
                spans.iter().map(|span| ("user", span.as_str())).collect();
            doc(&borrowed)
        })
        .collect()
}

fn output_offset(at: usize, commits: &[Commit]) -> usize {
    let mut out = at;
    for commit in commits {
        if commit.removed.end <= at {
            out -= commit.removed.len() - commit.anchor.len();
        }
    }
    out
}

#[test]
fn generated_log_bursts_converge_and_only_diverge_over_an_emitted_marker_or_an_anchor() {
    let opts = defaults();
    let payloads = generated_payloads(GENERATED_BURSTS);
    let mut compressor = Compressor::new();
    let mut out = Vec::new();
    let (mut compressed, mut divergent) = (0, 0);
    for payload in &payloads {
        compressor.compress(payload, &opts, &mut out);
        let once = out.clone();
        let first = compressor.commits().to_vec();
        if once.len() < payload.len() {
            compressed += 1;
        }
        compressor.compress(&once, &opts, &mut out);
        let twice = out.clone();
        if twice == once {
            continue;
        }
        divergent += 1;
        let anchors: Vec<(usize, usize)> = first
            .iter()
            .map(|commit| {
                (
                    output_offset(commit.anchor.start, &first),
                    output_offset(commit.anchor.end, &first),
                )
            })
            .collect();
        assert!(
            !compressor.commits().is_empty(),
            "a divergence must come from a group, not from nothing"
        );
        for commit in compressor.commits() {
            let removed = &once[commit.removed.clone()];
            let marker = removed.windows(5).any(|window| window == b" ...]");
            let anchor = anchors
                .iter()
                .any(|(start, end)| commit.removed.start < *end && *start < commit.removed.end);
            assert!(
                marker || anchor,
                "a second pass may only merge over an emitted marker or an anchor, got {:?} over {:?}",
                commit.kind,
                text(&removed[..removed.len().min(120)])
            );
        }
        compressor.compress(&twice, &opts, &mut out);
        assert_eq!(
            out, twice,
            "every payload must reach a fixed point within two recompressions"
        );
    }
    assert!(
        compressed * 2 >= payloads.len(),
        "only {compressed} of {} generated payloads compressed: the corpus is not exercising the stages",
        payloads.len()
    );
    assert!(
        divergent * 100 <= payloads.len() * 5,
        "{divergent} of {} generated payloads are not fixed points (3.15% measured, 5% ceiling)",
        payloads.len()
    );
}

#[test]
fn prior_marker_text_round_trips_untouched() {
    let payload = fixture("edges/prior-markers.json");
    let run = compress(&payload, &defaults());
    for marker in [
        "\u{27ea}\u{d7}200 identical \u{b7}c5f3\u{27eb}",
        "[... x50 rows, template 0abc ...]",
        "\u{27ea}block \u{d7}12 \u{b7}d4e5\u{27eb}",
    ] {
        assert!(
            text(&run.payload).contains(marker),
            "the prior marker {marker} did not round-trip"
        );
    }
    assert_eq!(run.stats.templated_blocks, 1);
    let again = compress(&run.payload, &defaults());
    assert_eq!(
        again.payload, run.payload,
        "the compressed form is a fixed point"
    );
    assert_eq!(again.stats.groups_collapsed, 0);
}

#[test]
fn every_json_output_parses() {
    for name in CORPUS.iter().filter(|name| !name.ends_with(".txt")) {
        let run = compress(&fixture(name), &defaults());
        assert_valid_json(&run.payload);
        assert_valid_json(&fixture(name));
    }
}

#[test]
fn the_output_equals_the_input_outside_the_patched_ranges() {
    for name in CORPUS {
        let payload = fixture(name);
        let run = compress(&payload, &defaults());
        let mut cursor = 0;
        let mut read = 0;
        for commit in &run.commits {
            let copied = commit.removed.start - read;
            assert_eq!(
                &run.payload[cursor..cursor + copied],
                &payload[read..commit.removed.start],
                "{name}"
            );
            cursor += copied;
            let anchor = &payload[commit.anchor.clone()];
            assert_eq!(&run.payload[cursor..cursor + anchor.len()], anchor);
            cursor += anchor.len();
            let marker = marker_at(&run.payload[cursor..], commit, anchor);
            cursor += marker.len();
            read = commit.removed.end;
        }
        let tail = payload.len() - read;
        assert_eq!(&run.payload[cursor..cursor + tail], &payload[read..]);
        assert_eq!(cursor + tail, run.payload.len());
    }
}

#[test]
fn the_output_is_valid_utf8_and_carries_no_escaped_marker_bytes() {
    for name in CORPUS {
        let run = compress(&fixture(name), &defaults());
        let _ = text(&run.payload);
        assert!(
            !run.payload.windows(2).any(|w| w == b"\\\\"),
            "{name} grew a backslash pair"
        );
    }
}

fn oracle(style: MarkerStyle, commit: &Commit, anchor: &[u8]) -> String {
    let (open, sep, close) = framing(style);
    let (prefix, suffix) = commit.kind.core(style);
    format!(
        "{open}{prefix}{}{suffix}{sep}{:04x}{close}",
        commit.count,
        marker_checksum(anchor)
    )
}

fn marker_at(rest: &[u8], commit: &Commit, anchor: &[u8]) -> String {
    let marker = oracle(commit.style, commit, anchor);
    assert!(
        rest.starts_with(marker.as_bytes()),
        "no {} marker for count {} follows the anchor in {:?}",
        commit.kind.core(commit.style).1,
        commit.count,
        text(&rest[..rest.len().min(64)])
    );
    marker
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ---------------------------------------------------------------- stats

#[test]
fn the_stats_carry_every_field_of_the_proto_message() {
    let payload = fixture("schemas/chat-minified.json");
    let run = compress(&payload, &defaults());
    assert_eq!(
        run.stats,
        Stats {
            bytes_in: payload.len() as u64,
            bytes_out: run.payload.len() as u64,
            approx_tokens_in: (payload.len() / 4) as u64,
            approx_tokens_out: (run.payload.len() / 4) as u64,
            groups_collapsed: 1,
            exact_runs: 0,
            ws_runs: 0,
            block_repeats: 0,
            template_groups: 1,
            degraded: false,
            noop_reason: None,
            elapsed_detect_ns: run.stats.elapsed_detect_ns,
            elapsed_compact_ns: run.stats.elapsed_compact_ns,
            elapsed_splice_ns: run.stats.elapsed_splice_ns,
            algo_version: ALGO_VERSION,
            templated_blocks: 0,
            options_echo: defaults().options_echo(),
            record_splits: 0,
        }
    );
    assert!(run.stats.bytes_out < run.stats.bytes_in);
    assert_eq!(run.stats.groups_collapsed, run.commits.len() as u64);
    assert_eq!(
        run.stats.groups_collapsed,
        run.stats.exact_runs
            + run.stats.ws_runs
            + run.stats.block_repeats
            + run.stats.template_groups
            + run.stats.templated_blocks
    );
}

#[test]
fn record_splits_counts_the_over_cap_lines_of_stage_one_b() {
    for (name, expect) in [
        ("edges/single-line-tool-dump-overcap.json", 1u64),
        ("edges/single-line-tool-dump-small.json", 0),
        ("edges/stage1b-no-separator-overcap.json", 1),
        ("edges/stage1b-record-len-16385.json", 1),
    ] {
        let run = compress(&fixture(name), &defaults());
        assert_eq!(run.stats.record_splits, expect, "{name}");
    }
    let dump = compress(
        &fixture("edges/single-line-tool-dump-overcap.json"),
        &defaults(),
    );
    assert_eq!(
        dump.stats.block_repeats, 1,
        "stage 1b records collapse through stage 5"
    );
    assert_eq!(
        dump.commits[0].count, 1022,
        "the four-record period is the anchor, not a shorter one"
    );
    assert!(dump.payload.len() < dump.stats.bytes_in as usize / 8);
    let wall = compress(&fixture("edges/stage1b-record-len-16385.json"), &defaults());
    assert_eq!(
        wall.payload,
        fixture("edges/stage1b-record-len-16385.json"),
        "an over-cap record is a wall"
    );
}

#[test]
fn the_algo_version_is_a_frozen_constant() {
    assert_eq!(ALGO_VERSION, "0.1.0");
    let run = compress(b"x", &defaults());
    assert_eq!(run.stats.algo_version, ALGO_VERSION);
}

#[test]
fn the_options_echo_is_the_resolved_canonical_json() {
    let opts = options(&RawOptions {
        scope_policy: Some(ScopePolicy::UserAndTools),
        min_group_size: Some(7),
        normalize_ws: Some(false),
        template_dedup: Some(false),
        marker_style: Some(MarkerStyle::Ascii),
        reversible: Some(true),
    });
    let run = compress(&fixture("schemas/chat-minified.json"), &opts);
    assert_eq!(
        run.stats.options_echo,
        r#"{"scope_policy":"user_and_tools","min_group_size":7,"normalize_ws":false,"template_dedup":false,"marker_style":"ascii","reversible":true}"#
    );
}

#[test]
fn a_forced_marker_style_reaches_the_output() {
    let payload = doc(&[("user", &joined(&log_burst(6)))]);
    let ascii = compress(
        &payload,
        &options(&RawOptions {
            marker_style: Some(MarkerStyle::Ascii),
            ..RawOptions::default()
        }),
    );
    assert!(text(&ascii.payload).contains("[... x5 rows, template"));
    assert!(!text(&ascii.payload).contains('\u{27ea}'));

    let unicode = compress(
        &payload,
        &options(&RawOptions {
            marker_style: Some(MarkerStyle::Unicode),
            ..RawOptions::default()
        }),
    );
    assert!(text(&unicode.payload).contains("\u{27ea}\u{d7}5 rows, template"));
}

#[test]
fn a_non_ascii_span_resolves_to_the_unicode_style() {
    let lines = (0..6)
        .map(|at| format!("2026-08-25T10:00:0{at}Z INFO caf\u{e9} 10.0.0.1 ok"))
        .collect::<Vec<_>>();
    let payload = doc(&[("user", &joined(&lines))]);
    let run = compress(&payload, &defaults());
    assert!(text(&run.payload).contains('\u{27ea}'));
    let forced = compress(
        &payload,
        &options(&RawOptions {
            marker_style: Some(MarkerStyle::Ascii),
            ..RawOptions::default()
        }),
    );
    assert!(text(&forced.payload).contains("[... x5 rows, template"));
}

#[test]
fn each_span_renders_in_its_own_resolved_style() {
    let ascii = joined(&log_burst(6));
    let unicode = joined(
        &(0..6)
            .map(|at| format!("2026-08-25T10:00:0{at}Z INFO caf\u{e9} 10.0.0.1 ok"))
            .collect::<Vec<_>>(),
    );
    let payload = doc(&[("user", &ascii), ("user", &unicode)]);
    let run = compress(&payload, &defaults());
    assert_eq!(run.commits.len(), 2);
    assert_eq!(run.commits[0].style, MarkerStyle::Ascii);
    assert_eq!(run.commits[1].style, MarkerStyle::Unicode);
    let rendered = text(&run.payload);
    assert!(
        rendered.contains("[... x5 rows, template"),
        "the all-ascii span keeps the ascii fallback: {rendered}"
    );
    assert!(
        rendered.contains("\u{27ea}\u{d7}5 rows, template"),
        "the non-ascii span gets the unicode marker: {rendered}"
    );
    assert_eq!(
        rendered.matches("[... x").count(),
        1,
        "one ascii marker only"
    );
    assert_eq!(
        rendered.matches('\u{27ea}').count(),
        1,
        "one unicode marker only"
    );
}

#[test]
fn reversible_is_echoed_but_still_not_honoured() {
    let payload = doc(&[("user", &joined(&log_burst(6)))]);
    let off = options(&RawOptions {
        reversible: Some(false),
        ..RawOptions::default()
    });
    let on = options(&RawOptions {
        reversible: Some(true),
        ..RawOptions::default()
    });
    let without = compress(&payload, &off);
    let with = compress(&payload, &on);
    assert_eq!(with.payload, without.payload);
    assert_eq!(with.commits, without.commits);
    assert!(
        without
            .stats
            .options_echo
            .ends_with(r#""reversible":false}"#)
    );
    assert!(with.stats.options_echo.ends_with(r#""reversible":true}"#));
}

// ---------------------------------------------------------------- determinism of the plumbing

struct Fixed(u64);

impl Clock for Fixed {
    fn now_ns(&self) -> u64 {
        self.0
    }
}

struct Counter(std::cell::Cell<u64>);

impl Clock for Counter {
    fn now_ns(&self) -> u64 {
        let next = self.0.get() + 1_000_000_000;
        self.0.set(next);
        next
    }
}

#[test]
fn timings_never_reach_the_payload() {
    let payload = fixture("schemas/chat-minified.json");
    let monotonic = compress(&payload, &defaults());
    let fixed = compress_with(&mut Compressor::with_clock(Fixed(7)), &payload, &defaults());
    let counted = compress_with(
        &mut Compressor::with_clock(Counter(std::cell::Cell::new(0))),
        &payload,
        &defaults(),
    );
    assert_eq!(monotonic.payload, fixed.payload);
    assert_eq!(monotonic.payload, counted.payload);
    assert_eq!(monotonic.commits, fixed.commits);
    assert_eq!(fixed.stats.elapsed_detect_ns, 0);
    assert_eq!(counted.stats.elapsed_detect_ns, 1_000_000_000);
    assert_eq!(counted.stats.elapsed_compact_ns, 1_000_000_000);
    assert_eq!(counted.stats.elapsed_splice_ns, 1_000_000_000);
}

#[test]
fn a_fixed_clock_makes_the_whole_stats_reproducible() {
    let mut first = None;
    for _ in 0..64 {
        let mut compressor = Compressor::with_clock(Fixed(11));
        let run = compress_with(
            &mut compressor,
            &fixture("schemas/chat-minified.json"),
            &defaults(),
        );
        match &first {
            None => first = Some(run),
            Some(expected) => assert_eq!(run.payload, expected.payload),
        }
    }
}

#[test]
fn a_fresh_and_a_warm_compressor_agree() {
    let corpus = chat_corpus();
    let mut warm = Compressor::new();
    let mut out = Vec::new();
    for _ in 0..3 {
        for (name, payload) in &corpus {
            let warm_run = compress_with(&mut warm, payload, &defaults());
            let cold_run = compress(payload, &defaults());
            assert_eq!(warm_run.payload, cold_run.payload, "{name}");
            assert_eq!(warm_run.commits, cold_run.commits, "{name}");
        }
    }
    for (_name, payload) in &corpus {
        warm.compress(payload, &defaults(), &mut out);
    }
    let capacity = out.capacity();
    for _ in 0..64 {
        warm.compress(&corpus[0].1, &defaults(), &mut out);
    }
    assert_eq!(out.capacity(), capacity, "the output buffer is reused");
}

#[test]
fn a_span_never_bleeds_into_its_neighbour() {
    let first = joined(&log_burst(6));
    let second = joined(&log_burst(6));
    let alone = compress(&doc(&[("user", &first)]), &defaults());
    let payload = doc(&[("user", &first), ("user", &second)]);
    let together = compress(&payload, &defaults());
    assert_eq!(alone.commits.len(), 1);
    assert_eq!(together.commits.len(), 2);
    assert_eq!(&together.commits[0], &alone.commits[0]);
    assert_eq!(
        text(&payload[together.commits[0].removed.end..together.commits[1].removed.start]),
        r#""},{"role":"user","content":""#,
        "the untouched bytes between the commits are exactly the envelope"
    );
    assert_eq!(
        together.commits[1].removed.len(),
        alone.commits[0].removed.len()
    );
    assert_eq!(together.commits[1].count, alone.commits[0].count);
}

fn uses(source: &str, banned: &str) -> bool {
    source
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|word| word == banned)
}

#[test]
fn the_pipeline_module_has_no_forbidden_determinism_inputs() {
    let source = include_str!("../src/pipeline.rs");
    assert!(
        !uses("let brand = 1;", "rand"),
        "the scan must not be a substring match"
    );
    assert!(
        uses("let x = rand::rng();", "rand"),
        "the scan must see a real use"
    );
    for banned in [
        "HashMap",
        "RandomState",
        "BTreeMap",
        "SystemTime",
        "env",
        "rand",
        "f32",
        "f64",
        "sort_by",
        "sort_unstable",
    ] {
        assert!(!uses(source, banned), "the pipeline must not use {banned}");
    }
    assert!(
        source.matches("now_ns()").count() == 4,
        "the clock is read exactly four times: the three stage boundaries"
    );
    let (before_clock, after_clock) = source
        .split_once("impl Clock for MonotonicClock")
        .expect("the monotonic clock");
    assert!(before_clock.contains("use std::time::Instant;"));
    assert!(
        !after_clock.contains("Instant"),
        "Instant is confined to the monotonic clock"
    );
    for required in [
        "resolve_style",
        "Ledger::new",
        "split_span_counted",
        "exact_runs",
        "ws_runs",
        "repeated_blocks",
        "template_groups",
        "templated_blocks",
        "splice_into",
        "locate_into",
        "sniff::sniff",
    ] {
        assert!(
            source.contains(required),
            "the pipeline must call {required}"
        );
    }
    let call_sites = [
        "stage1::split_span_counted(bytes)",
        "exact::exact_runs(",
        "wsruns::ws_runs(",
        "blocks::repeated_blocks(",
        "templ::template_groups(",
        "templ_blocks::templated_blocks(",
    ];
    let order: Vec<usize> = call_sites
        .iter()
        .map(|site| source.find(site).unwrap_or_else(|| panic!("{site}")))
        .collect();
    assert!(
        order.windows(2).all(|pair| pair[0] < pair[1]),
        "stages 1/1b, 3, 4, 5, 6 and 7 are called in normative order"
    );
    let at = |site: &str| source.find(site).unwrap_or_else(|| panic!("{site}"));
    assert!(
        at("let result = compact_span(") < at("splice_into(payload"),
        "every span is compacted before the single whole-payload splice"
    );
    let (detect, compact, splice) = (
        at("let detect_start"),
        at("let result = compact_span("),
        at("splice_into(payload"),
    );
    assert!(
        detect < compact && compact < splice,
        "detect, then compact, then splice"
    );
    assert!(
        at("options.normalize_ws") < at("options.template_dedup"),
        "the two option gates are checked in stage order"
    );
}

// ---------------------------------------------------------------- gate M2

#[test]
fn gate_m2_chat_outputs_are_byte_stable_over_1000_runs() {
    let corpus = chat_corpus();
    let opts = defaults();
    let mut compressor = Compressor::new();
    let mut out = Vec::new();
    let mut first: Option<Vec<Vec<u8>>> = None;
    for run in 0..1000u32 {
        let mut digests = Vec::with_capacity(corpus.len());
        for (_name, payload) in &corpus {
            compressor.compress(payload, &opts, &mut out);
            digests.push(out.clone());
        }
        match &first {
            None => first = Some(digests),
            Some(expected) => {
                for (at, (got, want)) in digests.iter().zip(expected).enumerate() {
                    assert_eq!(got, want, "run {run} of {} differs", corpus[at].0);
                }
            }
        }
    }
}

#[test]
fn the_stats_are_byte_stable_over_1000_runs_with_a_fixed_clock() {
    let corpus = chat_corpus();
    let opts = defaults();
    let mut out = Vec::new();
    let mut first: Option<Vec<Stats>> = None;
    for _ in 0..1000 {
        let mut compressor = Compressor::with_clock(Fixed(3));
        let stats = corpus
            .iter()
            .map(|(_, payload)| compressor.compress(payload, &opts, &mut out))
            .collect::<Vec<_>>();
        match &first {
            None => first = Some(stats),
            Some(expected) => assert_eq!(&stats, expected),
        }
    }
}

#[test]
fn m2_child_writes_the_corpus_outputs() {
    let Ok(path) = std::env::var(CHILD_BYTES_ENV) else {
        return;
    };
    let mut report = format!("seed {}\n", seed_fingerprint()).into_bytes();
    let opts = defaults();
    let mut compressor = Compressor::new();
    let mut out = Vec::new();
    for (name, payload) in chat_corpus() {
        compressor.compress(&payload, &opts, &mut out);
        report.extend_from_slice(name.as_bytes());
        report.push(b'\n');
        report.extend_from_slice(out.len().to_string().as_bytes());
        report.push(b'\n');
        report.extend_from_slice(&out);
        report.push(b'\n');
    }
    std::fs::write(path, report).expect("child writes its report");
}

struct Report {
    seed: String,
    entries: Vec<(String, Vec<u8>)>,
}

fn parse_report(bytes: &[u8]) -> Report {
    let line = |from: &mut usize| -> String {
        let rest = &bytes[*from..];
        let end = rest.iter().position(|b| *b == b'\n').expect("line end");
        let text = String::from_utf8(rest[..end].to_vec()).expect("utf-8 line");
        *from += end + 1;
        text
    };
    let mut at = 0;
    let seed = line(&mut at)
        .strip_prefix("seed ")
        .expect("seed")
        .to_string();
    let mut entries = Vec::new();
    while at < bytes.len() {
        let name = line(&mut at);
        let len: usize = line(&mut at).parse().expect("length");
        let payload = bytes[at..at + len].to_vec();
        at += len;
        assert_eq!(bytes[at], b'\n', "entry terminator");
        at += 1;
        entries.push((name, payload));
    }
    Report { seed, entries }
}

fn seed_fingerprint() -> String {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u8(0);
    format!("{:016x}", hasher.finish())
}

#[test]
fn gate_m2_outputs_are_identical_across_processes_and_environments() {
    if std::env::var(CHILD_BYTES_ENV).is_ok() {
        return;
    }
    let exe = std::env::current_exe().expect("test binary path");
    let dir = std::env::temp_dir().join("quantification-gate-m2");
    std::fs::create_dir_all(&dir).expect("report dir");
    let profiles: [(&str, &[(&str, &str)]); 2] = [
        (
            "profile-a",
            &[
                ("RUST_BACKTRACE", "0"),
                ("RAYON_NUM_THREADS", "1"),
                ("RUST_TEST_THREADS", "1"),
                ("LC_ALL", "C"),
                ("TZ", "UTC"),
            ],
        ),
        (
            "profile-b",
            &[
                ("RUST_BACKTRACE", "full"),
                ("RAYON_NUM_THREADS", "8"),
                ("RUST_TEST_THREADS", "4"),
                ("LC_ALL", "C.UTF-8"),
                ("TZ", "Pacific/Auckland"),
            ],
        ),
    ];

    let corpus = chat_corpus();
    let mut reports = Vec::new();
    for (name, env) in profiles {
        let report_path = dir.join(format!("{name}-{}.report", std::process::id()));
        let _ = std::fs::remove_file(&report_path);
        let status = Command::new(&exe)
            .arg("--exact")
            .arg(CHILD_TEST)
            .arg("--nocapture")
            .envs(env.iter().copied())
            .env(CHILD_BYTES_ENV, &report_path)
            .output()
            .expect("child runs");
        assert!(
            status.status.success(),
            "child {name} failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
        reports.push((
            name,
            parse_report(&std::fs::read(&report_path).expect("report")),
        ));
    }

    let seeds: Vec<&str> = reports
        .iter()
        .map(|(_, report)| report.seed.as_str())
        .collect();
    assert_ne!(
        seeds[0], seeds[1],
        "the two processes must carry different RandomState seeds ({seeds:?})"
    );

    for (name, report) in &reports {
        assert_eq!(report.entries.len(), corpus.len(), "{name}");
        for (at, (entry_name, entry_bytes)) in report.entries.iter().enumerate() {
            let (fixture_name, _) = &corpus[at];
            assert_eq!(entry_name, fixture_name, "{name} entry {at}");
            let local = compress(&corpus[at].1, &defaults());
            assert_eq!(
                &local.payload, entry_bytes,
                "{name} differs from the in-process run on {fixture_name}"
            );
        }
    }
    let mut compressed = 0;
    for (at, entry) in reports[0].1.entries.iter().enumerate() {
        assert_eq!(
            entry.1, reports[1].1.entries[at].1,
            "the two processes differ on {}",
            corpus[at].0
        );
        if entry.1 != corpus[at].1 {
            compressed += 1;
        }
    }
    assert!(
        compressed >= 4,
        "only {compressed} of {} chat fixtures changed: the gate is vacuous",
        corpus.len()
    );
}

#[test]
fn the_monotonic_clock_is_the_default_and_never_goes_backwards() {
    let clock = MonotonicClock::new();
    let first = clock.now_ns();
    let mut previous = first;
    for _ in 0..1000 {
        let now = clock.now_ns();
        assert!(now >= previous);
        previous = now;
    }
    assert!(previous >= first);
}

// ---------------------------------------------------------------- R3 oracle

fn assert_valid_json(bytes: &[u8]) {
    let stripped = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    let mut json = Json {
        bytes: stripped,
        at: 0,
        depth: 0,
    };
    json.value();
    json.ws();
    assert_eq!(json.at, stripped.len(), "trailing bytes after the document");
}

struct Json<'a> {
    bytes: &'a [u8],
    at: usize,
    depth: usize,
}

impl Json<'_> {
    fn ws(&mut self) {
        while matches!(self.bytes.get(self.at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn peek(&self) -> u8 {
        self.bytes
            .get(self.at)
            .copied()
            .unwrap_or_else(|| panic!("unexpected end of json at {}", self.at))
    }

    fn value(&mut self) {
        self.ws();
        self.depth += 1;
        assert!(self.depth <= 64, "json depth cap");
        match self.peek() {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => self.string(),
            b't' | b'f' | b'n' => self.keyword(),
            b'-' | b'0'..=b'9' => self.number(),
            other => panic!("unexpected byte {other:#04x} at {}", self.at),
        }
        self.depth -= 1;
    }

    fn keyword(&mut self) {
        for want in ["true", "false", "null"] {
            if self.bytes[self.at..].starts_with(want.as_bytes()) {
                self.at += want.len();
                return;
            }
        }
        panic!("unknown keyword at {}", self.at);
    }

    fn number(&mut self) {
        if self.peek() == b'-' {
            self.at += 1;
        }
        let int = self.digits();
        assert!(int > 0, "number without digits at {}", self.at);
        if self.bytes.get(self.at) == Some(&b'.') {
            self.at += 1;
            assert!(self.digits() > 0, "fraction without digits");
        }
        if matches!(self.bytes.get(self.at), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.bytes.get(self.at), Some(b'+' | b'-')) {
                self.at += 1;
            }
            assert!(self.digits() > 0, "exponent without digits");
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.at;
        while matches!(self.bytes.get(self.at), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        self.at - start
    }

    fn string(&mut self) {
        assert_eq!(self.peek(), b'"');
        self.at += 1;
        loop {
            let byte = self.peek();
            match byte {
                b'"' => {
                    self.at += 1;
                    return;
                }
                b'\\' => {
                    self.at += 1;
                    let escape = self.peek();
                    self.at += 1;
                    assert!(
                        escape.is_ascii_alphabetic()
                            || escape == b'\\'
                            || escape == b'/'
                            || escape == b'"',
                        "invalid escape at {}",
                        self.at
                    );
                }
                0..=0x1F => panic!("raw control byte in a string at {}", self.at),
                _ => self.at += 1,
            }
        }
    }

    fn object(&mut self) {
        self.at += 1;
        self.ws();
        if self.peek() == b'}' {
            self.at += 1;
            return;
        }
        loop {
            self.ws();
            self.string();
            self.ws();
            assert_eq!(self.peek(), b':');
            self.at += 1;
            self.value();
            self.ws();
            match self.peek() {
                b',' => self.at += 1,
                b'}' => {
                    self.at += 1;
                    return;
                }
                other => panic!("object byte {other:#04x} at {}", self.at),
            }
        }
    }

    fn array(&mut self) {
        self.at += 1;
        self.ws();
        if self.peek() == b']' {
            self.at += 1;
            return;
        }
        loop {
            self.value();
            self.ws();
            match self.peek() {
                b',' => self.at += 1,
                b']' => {
                    self.at += 1;
                    return;
                }
                other => panic!("array byte {other:#04x} at {}", self.at),
            }
        }
    }
}
