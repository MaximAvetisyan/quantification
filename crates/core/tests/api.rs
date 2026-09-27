use std::cell::Cell;
use std::path::{Path, PathBuf};

use quantification_core::api::{
    self, ALGO_VERSION, ApiError, Clock, Compressor, ContentType, Request, Stats,
};
use quantification_core::config::{MarkerStyle, RawOptions, ResolveError, ScopePolicy};

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

const API_SOURCE: &str = include_str!("../src/api.rs");

const PUBLIC_ITEMS: &[&str] = &[
    "ALGO_VERSION",
    "ApiError",
    "Clock",
    "Compressor",
    "ContentType",
    "MarkerStyle",
    "MonotonicClock",
    "NoopReason",
    "RawOptions",
    "Request",
    "ResolveError",
    "STRICT_VALIDATE",
    "Sink",
    "ScopePolicy",
    "Stats",
    "as_str",
    "compress",
    "new",
    "pinned",
    "reserve",
    "with_clock",
    "with_options",
    "with_sink",
];

const PARAMETERS: &[&str] = &[
    "self",
    "payload",
    "out",
    "request",
    "clock",
    "sink",
    "content_type",
    "options",
    "input_len",
];

const SIGNATURE_TYPES: &[&str] = &[
    "Self",
    "ApiError",
    "Clock",
    "Compressor",
    "Sink",
    "ContentType",
    "RawOptions",
    "Request",
    "Result",
    "Stats",
    "pub",
    "impl",
    "static",
    "fn",
    "mut",
    "bool",
    "u8",
    "u64",
    "usize",
    "str",
    "char",
    "Option",
    "Some",
    "Vec",
    "pinned",
    "sniffed",
];

fn root(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

fn fixture(rel: &str) -> Vec<u8> {
    let path = root(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn golden(name: &str) -> Vec<u8> {
    let base = name.rsplit('/').next().expect("fixture name");
    fixture(&format!("golden/{base}"))
}

fn corpus() -> Vec<(String, Vec<u8>)> {
    CORPUS
        .iter()
        .map(|name| (name.to_string(), fixture(name)))
        .collect()
}

fn defaults() -> RawOptions {
    RawOptions::default()
}

fn request(content_type: Option<ContentType>, options: RawOptions) -> Request {
    Request {
        content_type,
        options,
    }
}

fn compress(payload: &[u8], request: &Request) -> (Vec<u8>, Stats) {
    let mut out = Vec::new();
    let stats = Compressor::new()
        .compress(payload, request, &mut out)
        .expect("an unpinned request never errors");
    (out, stats)
}

fn error_of(payload: &[u8], request: &Request) -> ApiError {
    let mut out = Vec::new();
    Compressor::new()
        .compress(payload, request, &mut out)
        .expect_err("this request must be refused")
}

fn log_lines(count: usize) -> String {
    (0..count)
        .map(|at| format!("2026-08-25T20:00:{at:02}Z INFO svc 10.10.0.{at} ok"))
        .collect::<Vec<_>>()
        .join(r"\n")
}

fn repeated(line: &str, count: usize) -> String {
    vec![line.to_string(); count].join(r"\n")
}

fn chat(content: &str) -> Vec<u8> {
    format!(r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"{content}"}}]}}"#)
        .into_bytes()
}

fn tool_result(content: &str) -> Vec<u8> {
    format!(
        r#"{{"model":"claude","max_tokens":8,"messages":[{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"tu_1","content":"{content}"}}]}}]}}"#
    )
    .into_bytes()
}

fn sniff(payload: &[u8]) -> Option<ContentType> {
    quantification_core::sniff::sniff(payload)
}

fn tokens(text: &str) -> Vec<&str> {
    text.split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|word| !word.is_empty())
        .collect()
}

fn uses(source: &str, banned: &str) -> bool {
    tokens(source).contains(&banned)
}

fn public_lines() -> Vec<&'static str> {
    API_SOURCE
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("pub "))
        .collect()
}

fn block(header: &str) -> &'static str {
    let start = API_SOURCE.find(header).expect(header) + header.len();
    let end = start + API_SOURCE[start..].find("\n}").expect("the end of a block");
    &API_SOURCE[start..end]
}

fn declared_items() -> Vec<String> {
    let mut items = Vec::new();
    for line in public_lines() {
        let rest = line.strip_prefix("pub ").expect("a public line");
        if let Some(path) = rest.strip_prefix("use ") {
            let list = path
                .split_once('{')
                .map(|(_, tail)| tail.trim_end_matches("};").to_string())
                .unwrap_or_else(|| path.trim_end_matches(';').to_string());
            for entry in list.split(',') {
                let name = entry.trim().rsplit(" as ").next().unwrap_or("");
                items.push(name.rsplit("::").next().unwrap_or("").to_string());
            }
        } else {
            let (head, tail) = rest.split_once(' ').expect("a named item");
            if head.ends_with(':') {
                continue;
            }
            items.push(
                tail.split(['(', ' ', '<', '{', ':'])
                    .next()
                    .expect("a name")
                    .to_string(),
            );
        }
    }
    items.sort();
    items
}

// ---------------------------------------------------------------- public surface

#[test]
fn the_public_surface_is_exactly_the_documented_items() {
    let mut expected: Vec<String> = PUBLIC_ITEMS.iter().map(|item| item.to_string()).collect();
    expected.sort();
    assert_eq!(declared_items(), expected);
}

#[test]
fn no_public_signature_exposes_an_internal_type() {
    let functions: Vec<&'static str> = public_lines()
        .iter()
        .filter(|line| line.starts_with("pub fn "))
        .copied()
        .collect();
    let fields: Vec<&str> = block("pub struct Request {")
        .lines()
        .chain(block("pub enum ApiError {").lines())
        .map(str::trim)
        .filter(|line| {
            line.starts_with("pub ") || line.starts_with("pinned:") || line.starts_with("sniffed:")
        })
        .collect();
    assert_eq!(functions.len(), 8, "the public functions are {functions:?}");
    assert_eq!(
        fields,
        [
            "pub content_type: Option<ContentType>,",
            "pub options: RawOptions,",
            "pinned: ContentType,",
            "sniffed: Option<ContentType>,",
        ]
    );
    let compressor = block("pub struct Compressor {");
    assert!(
        !compressor
            .lines()
            .any(|line| line.trim_start().starts_with("pub ")),
        "the wrapped pipeline compressor is a private field"
    );
    assert!(compressor.contains("pipeline::Compressor"));
    for line in functions.iter().chain(fields.iter()) {
        let words = tokens(line);
        let name = if line.starts_with("pub fn ") {
            [words[2]]
        } else {
            [""]
        };
        for token in words {
            if token == name[0] || PARAMETERS.contains(&token) {
                continue;
            }
            assert!(
                SIGNATURE_TYPES.contains(&token),
                "{token} in the public line `{line}` is not a public type"
            );
        }
    }
    let leak = "pub fn commits(&mut self) -> &[Commit];";
    assert!(
        tokens(leak).contains(&"Commit"),
        "the scan reads the whole line"
    );
    assert!(
        tokens(leak)
            .iter()
            .any(|token| !SIGNATURE_TYPES.contains(token) && !PARAMETERS.contains(token)),
        "the scan must reject a synthetic leak"
    );
    for internal in [
        "Commit",
        "Span",
        "Ledger",
        "Scratch",
        "StageStats",
        "Detected",
    ] {
        assert!(!SIGNATURE_TYPES.contains(&internal));
    }
}

#[test]
fn the_api_module_cannot_reach_the_detectors_the_ledger_or_the_fingerprint_tables() {
    for banned in [
        "detect",
        "ledger",
        "fingerprint",
        "mask",
        "keys",
        "stage1",
        "stage1b",
        "wsnorm",
        "s1",
        "render",
        "Commit",
        "Span",
        "Scratch",
        "StageStats",
        "Ledger",
    ] {
        assert!(
            !uses(API_SOURCE, banned),
            "the api module must not name {banned}"
        );
    }
    for allowed in ["config", "pipeline", "sniff", "splice", "locator"] {
        assert!(
            uses(API_SOURCE, allowed),
            "the api module must reach {allowed}"
        );
    }
    assert!(
        !uses("let brand = 1;", "rand"),
        "the scan is not a substring match"
    );
    assert!(uses("rand::rng()", "rand"), "the scan must see a real use");
    for banned in [
        "HashMap",
        "RandomState",
        "BTreeMap",
        "SystemTime",
        "Instant",
        "env",
        "rand",
        "f32",
        "f64",
        "sort_by",
        "sort_unstable",
        "tokio",
        "std::io",
        "std::fs",
        "thread",
    ] {
        assert!(!uses(API_SOURCE, banned), "the api must not use {banned}");
    }
    assert!(
        !API_SOURCE.contains("//"),
        "the api module carries no comment"
    );
}

#[test]
fn the_api_module_never_reads_a_clock_itself() {
    assert!(
        !uses(API_SOURCE, "now_ns"),
        "the api module must not read the clock"
    );
    assert!(
        !uses(API_SOURCE, "Instant"),
        "the api module has no clock of its own"
    );
    assert_eq!(
        tokens(API_SOURCE)
            .iter()
            .filter(|token| **token == "clock")
            .count(),
        2,
        "the clock is a parameter of with_clock and the argument it forwards"
    );
    for line in public_lines() {
        if line.starts_with("pub use ") {
            continue;
        }
        assert!(
            !line.contains("pipeline::") && !line.contains("splice::"),
            "the internal type {line} is not reachable through a public item"
        );
    }
}

// ---------------------------------------------------------------- options

#[test]
fn the_seven_defaults_reach_the_echo_end_to_end() {
    let (_out, stats) = compress(&chat("a"), &Request::default());
    assert_eq!(
        stats.options_echo,
        concat!(
            r#"{"scope_policy":"user_content","min_group_size":3,"normalize_ws":true,"#,
            r#""template_dedup":true,"marker_style":"auto","reversible":false}"#
        )
    );
    assert_eq!(stats.algo_version, ALGO_VERSION);
    assert_eq!(api::ALGO_VERSION, "0.1.0");
}

#[test]
fn every_option_reaches_the_echo_in_the_section_six_one_order() {
    let (out, stats) = compress(
        &chat("a"),
        &request(
            None,
            RawOptions {
                scope_policy: Some(ScopePolicy::UserAndTools),
                min_group_size: Some(7),
                normalize_ws: Some(false),
                template_dedup: Some(false),
                marker_style: Some(MarkerStyle::Unicode),
                reversible: Some(false),
            },
        ),
    );
    assert_eq!(
        out,
        b"{\"model\":\"gpt-4o\",\"messages\":[{\"role\":\"user\",\"content\":\"a\"}]}"
    );
    assert_eq!(
        stats.options_echo,
        concat!(
            r#"{"scope_policy":"user_and_tools","min_group_size":7,"normalize_ws":false,"#,
            r#""template_dedup":false,"marker_style":"unicode","reversible":false}"#
        )
    );
}

#[test]
fn a_resolved_option_reaches_the_compaction_and_not_only_the_echo() {
    let line = "a plain repeated log line with no maskable field at all";
    let payload = chat(&repeated(line, 3));
    let without_templates = RawOptions {
        template_dedup: Some(false),
        ..defaults()
    };
    let (at_three, three) = compress(
        &payload,
        &request(
            None,
            RawOptions {
                min_group_size: Some(3),
                ..without_templates.clone()
            },
        ),
    );
    let (at_four, four) = compress(
        &payload,
        &request(
            None,
            RawOptions {
                min_group_size: Some(4),
                ..without_templates
            },
        ),
    );
    assert_eq!(three.exact_runs, 1, "stage 3 claims the run");
    assert_eq!(three.groups_collapsed, 1);
    assert_eq!(four.exact_runs, 0, "the run stages honour the floor");
    assert_eq!(four.groups_collapsed, 0);
    assert_eq!(at_four, payload);
    assert!(at_three.len() < at_four.len());
    assert!(three.options_echo.contains(r#""min_group_size":3"#));
    assert!(four.options_echo.contains(r#""min_group_size":4"#));
}

#[test]
fn min_group_size_does_not_gate_the_templated_block_stage() {
    let line = "a plain repeated log line with no maskable field at all";
    let payload = chat(&repeated(line, 3));
    let (out, stats) = compress(
        &payload,
        &request(
            None,
            RawOptions {
                min_group_size: Some(4),
                ..defaults()
            },
        ),
    );
    assert_eq!(stats.exact_runs, 0);
    assert_eq!(stats.templated_blocks, 1, "stage 7's minimum is a period");
    assert_ne!(out, payload);
    let (verbatim, none) = compress(
        &payload,
        &request(
            None,
            RawOptions {
                min_group_size: Some(4),
                template_dedup: Some(false),
                ..defaults()
            },
        ),
    );
    assert_eq!(none.templated_blocks, 0);
    assert_eq!(verbatim, payload);
}

#[test]
fn a_forced_marker_style_reaches_the_output() {
    let line = "a plain repeated log line with no maskable field at all";
    let payload = chat(&repeated(line, 3));
    let styled = |style| {
        compress(
            &payload,
            &request(
                None,
                RawOptions {
                    marker_style: Some(style),
                    ..defaults()
                },
            ),
        )
        .0
    };
    let unicode = String::from_utf8_lossy(&styled(MarkerStyle::Unicode)).into_owned();
    let ascii = String::from_utf8_lossy(&styled(MarkerStyle::Ascii)).into_owned();
    let auto = String::from_utf8_lossy(&styled(MarkerStyle::Auto)).into_owned();
    assert!(
        unicode.contains('\u{27ea}') && unicode.contains("identical"),
        "{unicode}"
    );
    assert!(
        ascii.contains("[... ") && ascii.contains("identical"),
        "{ascii}"
    );
    assert_eq!(auto, ascii, "the payload is all ascii");
}

#[test]
fn the_scope_policy_selects_a_tool_span_only_under_user_and_tools() {
    let payload = tool_result(&log_lines(4));
    let (user_out, user_stats) = compress(&payload, &Request::default());
    let (tool_out, tool_stats) = compress(
        &payload,
        &request(
            None,
            RawOptions {
                scope_policy: Some(ScopePolicy::UserAndTools),
                ..defaults()
            },
        ),
    );
    assert_eq!(user_out, payload);
    assert_eq!(user_stats.groups_collapsed, 0);
    assert_eq!(tool_stats.groups_collapsed, 1);
    assert!(tool_out.len() < user_out.len());
}

#[test]
fn a_reserved_option_is_an_options_error_and_not_a_degrade() {
    for policy in [ScopePolicy::AllMessages, ScopePolicy::ExplicitPaths] {
        assert_eq!(
            error_of(
                &chat("a"),
                &request(
                    None,
                    RawOptions {
                        scope_policy: Some(policy),
                        ..defaults()
                    }
                )
            ),
            ApiError::Options(ResolveError::UnsupportedScopePolicy(policy))
        );
    }
    assert_eq!(
        error_of(
            &chat("a"),
            &request(
                None,
                RawOptions {
                    min_group_size: Some(1),
                    ..defaults()
                }
            )
        )
        .as_str(),
        "invalid_options"
    );
    assert_eq!(
        ApiError::Options(ResolveError::MinGroupSizeBelowTwo(1)).to_string(),
        "invalid_options: MinGroupSizeBelowTwo(1)"
    );
}

#[test]
fn reversible_true_resolves_echoes_true_and_changes_no_output_byte() {
    let payload = chat(&log_lines(4));
    let (on, stats) = compress(
        &payload,
        &request(
            None,
            RawOptions {
                reversible: Some(true),
                ..defaults()
            },
        ),
    );
    let (off, off_stats) = compress(
        &payload,
        &request(
            None,
            RawOptions {
                reversible: Some(false),
                ..defaults()
            },
        ),
    );
    let (without, _) = compress(&payload, &Request::default());
    assert_eq!(on, off, "reversibility is metadata and perturbs no byte");
    assert_eq!(on, without);
    assert!(stats.options_echo.ends_with(r#""reversible":true}"#));
    assert!(off_stats.options_echo.ends_with(r#""reversible":false}"#));
    assert_eq!(stats.bytes_out, on.len() as u64);
    assert!(
        stats.restore_ids.is_empty(),
        "no sink is wired through this call, so no id is promised"
    );
}

#[test]
fn a_wired_sink_receives_the_committed_range_of_every_group() {
    let line = "ERROR timeout while connecting to the primary database shard";
    let payload = chat(&repeated(line, 4));
    let store = quantification_core::ccr::Shared::default();
    let mut out = Vec::new();
    let stats = Compressor::new()
        .with_sink(store.clone())
        .compress(
            &payload,
            &request(
                None,
                RawOptions {
                    reversible: Some(true),
                    ..defaults()
                },
            ),
            &mut out,
        )
        .expect("reversible=true resolves");
    assert_eq!(stats.groups_collapsed, 1);
    assert_eq!(stats.restore_ids.len(), 1);
    assert_eq!(
        store.restore(Some(&out), &stats.restore_ids[0]),
        Some(repeated(line, 4).into_bytes()),
        "the stored original is the range the marker replaced"
    );
}

// ---------------------------------------------------------------- pass-through

#[test]
fn an_unknown_schema_passes_through_with_a_degrade_and_a_noop_reason() {
    let payload = b"{\"foo\":1,\"bar\":[1,2,3]}".to_vec();
    let (out, stats) = compress(&payload, &Request::default());
    assert_eq!(out, payload);
    assert!(stats.degraded);
    assert_eq!(stats.noop_reason, Some(api::NoopReason::UnknownSchema));
    assert_eq!(
        stats.noop_reason.map(|r| r.as_str()),
        Some("unknown_schema")
    );
    assert_eq!(stats.groups_collapsed, 0);
    assert_eq!(stats.bytes_in, payload.len() as u64);
    assert_eq!(stats.bytes_out, out.len() as u64);
}

#[cfg(not(feature = "strict_validate"))]
#[test]
fn a_malformed_document_passes_through_untouched() {
    let payload = b"{\"messages\":[{\"role\":\"user\",\"content\":\"a\\nb".to_vec();
    let (out, stats) = compress(&payload, &Request::default());
    assert_eq!(out, payload);
    assert!(stats.degraded);
    assert_eq!(stats.noop_reason, Some(api::NoopReason::Malformed));
    assert_eq!(stats.noop_reason.map(|r| r.as_str()), Some("malformed"));
}
#[test]
fn the_degenerate_payloads_never_error() {
    for payload in [
        &b""[..],
        b"   \n\t ",
        b"null",
        b"{}",
        b"[]",
        b"\"a bare string\"",
        b"{\"messages\":[]}",
    ] {
        let (out, stats) = compress(payload, &Request::default());
        assert_eq!(out, payload, "{payload:?} is a byte-for-byte pass-through");
        assert!(!stats.degraded || stats.noop_reason.is_some());
    }
}

#[test]
fn no_fixture_of_the_corpus_is_ever_refused() {
    for (name, payload) in corpus() {
        let (out, stats) = compress(&payload, &Request::default());
        assert_eq!(stats.bytes_out, out.len() as u64, "{name}");
        assert_eq!(stats.bytes_in, payload.len() as u64, "{name}");
    }
}

// ---------------------------------------------------------------- pinned content type

#[test]
fn a_pin_the_payload_agrees_with_compresses() {
    let payload = chat(&log_lines(4));
    assert_eq!(sniff(&payload), Some(ContentType::Chat));
    let (pinned, stats) = compress(&payload, &Request::pinned(ContentType::Chat));
    assert_eq!(stats.groups_collapsed, 1);
    assert_eq!(pinned, compress(&payload, &Request::default()).0);
}

#[test]
fn a_text_pin_compresses_the_whole_buffer() {
    let payload = log_lines(4).into_bytes();
    let (out, stats) = compress(&payload, &Request::pinned(ContentType::Text));
    assert_eq!(stats.groups_collapsed, 1);
    assert!(out.len() < payload.len());
    assert!(
        String::from_utf8_lossy(&out).contains("x3 rows, template"),
        "{}",
        String::from_utf8_lossy(&out)
    );
    assert_eq!(out, compress(&payload, &Request::default()).0);
}

#[test]
fn a_pin_the_payload_plainly_contradicts_is_a_typed_error() {
    let chat_payload = chat(&log_lines(4));
    let text_payload = log_lines(4).into_bytes();
    let responses_payload = b"{\"input\":\"a\\nb\\nc\\nd\"}".to_vec();
    for (payload, pinned, sniffed) in [
        (&text_payload, ContentType::Chat, Some(ContentType::Text)),
        (
            &text_payload,
            ContentType::Responses,
            Some(ContentType::Text),
        ),
        (
            &text_payload,
            ContentType::Messages,
            Some(ContentType::Text),
        ),
        (
            &chat_payload,
            ContentType::Responses,
            Some(ContentType::Chat),
        ),
        (
            &responses_payload,
            ContentType::Chat,
            Some(ContentType::Responses),
        ),
        (
            &responses_payload,
            ContentType::Messages,
            Some(ContentType::Responses),
        ),
        (&b"{\"foo\":1}".to_vec(), ContentType::Chat, None),
        (&b"{\"foo\":1}".to_vec(), ContentType::Responses, None),
    ] {
        assert_eq!(
            error_of(payload, &Request::pinned(pinned)),
            ApiError::ContentTypeMismatch { pinned, sniffed },
            "pinning {pinned:?} against a payload that sniffs as {sniffed:?}"
        );
        assert_eq!(
            error_of(payload, &Request::pinned(pinned)).as_str(),
            "content_type_mismatch"
        );
    }
}

#[test]
fn a_pin_on_a_malformed_document_is_a_contradiction() {
    let payload = b"{\"messages\":[{\"role\":\"user\",\"content\":\"a\\nb".to_vec();
    assert_eq!(
        error_of(&payload, &Request::pinned(ContentType::Chat)),
        ApiError::ContentTypeMismatch {
            pinned: ContentType::Chat,
            sniffed: Some(ContentType::Chat)
        }
    );
}

#[test]
fn a_contradiction_is_an_error_while_an_unknown_schema_is_a_pass_through() {
    let payload = b"{\"foo\":1,\"bar\":2}".to_vec();
    assert!(matches!(
        Compressor::new().compress(
            &payload,
            &Request::pinned(ContentType::Chat),
            &mut Vec::new()
        ),
        Err(ApiError::ContentTypeMismatch { .. })
    ));
    let (out, stats) = compress(&payload, &Request::default());
    assert_eq!(out, payload);
    assert!(stats.degraded);
    assert_eq!(stats.noop_reason, Some(api::NoopReason::UnknownSchema));
}

#[test]
fn the_pin_decides_the_schema_and_not_the_sniff() {
    let payload = tool_result(&log_lines(4));
    let with_tools = RawOptions {
        scope_policy: Some(ScopePolicy::UserAndTools),
        ..defaults()
    };
    assert_eq!(sniff(&payload), Some(ContentType::Messages));
    let (auto, auto_stats) = compress(&payload, &request(None, with_tools.clone()));
    let (as_messages, messages_stats) = compress(
        &payload,
        &request(Some(ContentType::Messages), with_tools.clone()),
    );
    let (as_chat, chat_stats) = compress(&payload, &request(Some(ContentType::Chat), with_tools));
    assert_eq!(messages_stats.groups_collapsed, 1);
    assert_eq!(as_messages, auto, "the sniff already says messages");
    assert_eq!(
        as_chat, payload,
        "a chat pin leaves a tool_result block alone"
    );
    assert_eq!(chat_stats.groups_collapsed, 0);
    assert!(as_messages.len() < as_chat.len(), "the pin is not a no-op");
    assert!(!auto_stats.degraded);
}

// ---------------------------------------------------------------- equivalence and determinism

#[test]
fn the_chat_goldens_are_reproduced_through_the_public_api() {
    let mut changed = 0;
    for name in CHAT_CORPUS {
        let (out, _) = compress(&fixture(name), &Request::default());
        assert_eq!(out, golden(name), "{name} does not reproduce its golden");
        if out != fixture(name) {
            changed += 1;
        }
    }
    assert!(changed >= 4, "only {changed} fixtures changed");
}

#[test]
fn an_auto_and_a_matching_pin_agree_byte_for_byte() {
    for (name, payload) in corpus() {
        let (auto, stats) = compress(&payload, &Request::default());
        let Some(sniffed) = sniff(&payload) else {
            assert_eq!(auto, payload, "{name}");
            continue;
        };
        let (pinned, pinned_stats) = compress(&payload, &Request::pinned(sniffed));
        assert_eq!(auto, pinned, "{name}");
        assert_eq!(stats.bytes_out, pinned_stats.bytes_out, "{name}");
        assert_eq!(stats.degraded, pinned_stats.degraded, "{name}");
        assert_eq!(stats.noop_reason, pinned_stats.noop_reason, "{name}");
        assert_eq!(stats.options_echo, pinned_stats.options_echo, "{name}");
    }
}

#[test]
fn repeated_calls_are_byte_identical() {
    let mut compressor = Compressor::new();
    let mut out = Vec::new();
    let mut first: Option<Vec<Vec<u8>>> = None;
    for _ in 0..64 {
        let mut digests = Vec::new();
        for (_name, payload) in corpus() {
            compressor
                .compress(&payload, &Request::default(), &mut out)
                .expect("the corpus is never refused");
            digests.push(out.clone());
        }
        match &first {
            None => first = Some(digests),
            Some(expected) => assert_eq!(&digests, expected),
        }
    }
}

struct Hostile {
    calls: Cell<u64>,
}

#[cfg(feature = "bench_stages")]
fn clock_budget() -> (u64, &'static str) {
    (
        4 + 2 * quantification_core::pipeline::Stage::ALL.len() as u64,
        "the public api reads the clock at the three stage boundaries plus one mark and one read per §4.4 stage under bench_stages",
    )
}

#[cfg(not(feature = "bench_stages"))]
fn clock_budget() -> (u64, &'static str) {
    (
        4,
        "the public api reads the clock only at the three stage boundaries",
    )
}

impl Clock for Hostile {
    fn now_ns(&self) -> u64 {
        let next = self.calls.get() + 1;
        self.calls.set(next);
        let (budget, why) = clock_budget();
        assert!(next <= budget, "{why}");
        if next % 2 == 1 { u64::MAX } else { 0 }
    }
}

#[test]
fn a_pathological_clock_cannot_change_the_output() {
    let (name, payload) = corpus().into_iter().next().expect("a fixture");
    let mut hostile = Compressor::with_clock(Hostile {
        calls: Cell::new(0),
    });
    let mut out = Vec::new();
    let stats = hostile
        .compress(&payload, &Request::default(), &mut out)
        .expect("a valid request");
    let (monotonic, _) = compress(&payload, &Request::default());
    assert_eq!(out, monotonic, "{name} changed under a hostile clock");
    assert_eq!(stats.elapsed_detect_ns, 0);
    assert_eq!(stats.elapsed_compact_ns, u64::MAX);
    assert_eq!(stats.elapsed_splice_ns, 0);
    assert_eq!(stats.bytes_out, out.len() as u64);
}

#[test]
fn the_reserved_buffer_is_reused_and_never_reallocates() {
    let mut compressor = Compressor::new();
    let mut out = Vec::new();
    for _ in 0..64 {
        for (_name, payload) in corpus() {
            api::reserve(&mut out, payload.len());
            let capacity = out.capacity();
            let stats = compressor
                .compress(&payload, &Request::default(), &mut out)
                .expect("the corpus is never refused");
            assert_eq!(out.capacity(), capacity, "the reserved buffer grew");
            assert!(capacity as u64 >= stats.bytes_out);
        }
    }
}

#[test]
fn the_reservation_bounds_every_possible_output() {
    for (name, payload) in corpus() {
        let mut out = Vec::new();
        api::reserve(&mut out, payload.len());
        assert!(out.capacity() >= payload.len(), "{name}");
        let (_, stats) = compress(&payload, &Request::default());
        assert!(
            stats.bytes_out <= payload.len() as u64,
            "{name}: the profitability gate never grows the payload"
        );
    }
}

// ---------------------------------------------------------------- strict_validate

#[test]
fn the_flag_is_reported_to_callers() {
    assert_eq!(api::STRICT_VALIDATE, cfg!(feature = "strict_validate"));
}

#[test]
fn the_default_build_carries_no_validator() {
    let stub = concat!(
        "#[cfg(not(feature = \"strict_validate\"))]\n",
        "fn strict(_payload: &[u8], _pinned: Option<ContentType>) -> Result<(), ApiError> {\n",
        "    Ok(())\n",
        "}"
    );
    assert!(API_SOURCE.contains(stub), "the default build's stub moved");
    let parser = API_SOURCE.find("struct Parser").expect("the parser");
    let gate = API_SOURCE[..parser].lines().last().expect("a line");
    assert_eq!(gate.trim(), r#"#[cfg(feature = "strict_validate")]"#);
}

#[cfg(not(feature = "strict_validate"))]
#[test]
fn without_the_flag_a_malformed_payload_degrades_to_pass_through() {
    for payload in [
        &b"{\"messages\":[],\"n\":01}"[..],
        &b"{\"messages\":[{\"role\":\"user\",\"content\":\"x\\q\"}]}"[..],
        &b"{\"messages\":[],\"n\":1.}"[..],
        &b"{\"messages\":[]}"[..],
        b"{messages:[]}",
    ] {
        let (out, _stats) = compress(payload, &Request::default());
        assert_eq!(
            out,
            payload,
            "{payload:?} is a pass-through, not an error (STRICT_VALIDATE={})",
            api::STRICT_VALIDATE
        );
    }
}

#[cfg(feature = "strict_validate")]
#[test]
fn with_the_flag_a_malformed_payload_is_a_typed_error() {
    for payload in [
        &b"{\"messages\":[],\"n\":01}"[..],
        &b"{\"messages\":[{\"role\":\"user\",\"content\":\"x\\q\"}]}"[..],
        &b"{\"messages\":[],\"n\":1e}"[..],
        &b"{\"messages\":[],\"n\":1.}"[..],
        &b"{\"messages\":[],\"n\":-}"[..],
        &b"{\"messages\":[],\"n\":tru}"[..],
        &b"{\"messages\":[],}"[..],
        &b"{\"messages\":[],\"n\":1,}"[..],
        &b"{\"messages\":[],\"n\":+1}"[..],
        &b"{\"messages\":[],\"n\":1}{\"x\":1}"[..],
        &b"{messages:[]}"[..],
        &b"{\"messages\":[],\"n\":1} x"[..],
        &b"{\"messages\":[],\"n\":\"\x01\"}"[..],
        &b"{\"messages\":[],\"n\":\"\\u00zz\"}"[..],
        &b"{\"messages\":[]"[..],
    ] {
        assert_eq!(
            error_of(payload, &Request::default()),
            ApiError::Malformed,
            "{payload:?} is not a JSON document (STRICT_VALIDATE={})",
            api::STRICT_VALIDATE
        );
    }
}

#[cfg(feature = "strict_validate")]
#[test]
fn with_the_flag_a_valid_payload_is_untouched_by_the_parse() {
    for name in CHAT_CORPUS {
        let (out, _) = compress(&fixture(name), &Request::default());
        assert_eq!(out, golden(name), "{name} does not reproduce its golden");
    }
    for (name, payload) in corpus() {
        let mut plain = Vec::new();
        let stats = quantification_core::pipeline::Compressor::new().compress(
            &payload,
            &quantification_core::config::resolve(&defaults()).expect("the defaults resolve"),
            &mut plain,
        );
        let (out, api_stats) = compress(&payload, &Request::default());
        assert_eq!(out, plain, "{name} changed under strict_validate");
        assert_eq!(api_stats.bytes_out, stats.bytes_out, "{name}");
        assert_eq!(api_stats.degraded, stats.degraded, "{name}");
    }
    for payload in [
        &b"{\"a\":[1,2,{\"b\":null},true,false,-0.5e+10]}"[..],
        b"\xef\xbb\xbf{\"messages\":[]}",
        b"{\"u\":\"\\u0041\\ud83d\\ude00\"}",
        b"  {\"a\" : 1 }  ",
        &b"{\"a\":1.5e-3}"[..],
        &b"{\"a\":0}"[..],
    ] {
        let (out, _) = compress(payload, &Request::default());
        assert_eq!(out, payload);
    }
}

#[cfg(feature = "strict_validate")]
#[test]
fn the_parse_agrees_with_the_locator_on_the_depth_cap() {
    let nest = |depth: usize| {
        let mut payload = b"{\"messages\":[],\"x\":".to_vec();
        payload.extend(std::iter::repeat_n(b'[', depth));
        payload.extend(std::iter::repeat_n(b']', depth));
        payload.push(b'}');
        payload
    };
    for depth in [1, 62, 63] {
        let payload = nest(depth);
        let (out, stats) = compress(&payload, &Request::default());
        assert_eq!(out, payload, "depth {depth} is inside the cap");
        assert!(!stats.degraded, "depth {depth} is inside the cap");
    }
    for depth in [64, 70] {
        assert_eq!(
            error_of(&nest(depth), &Request::default()),
            ApiError::Malformed,
            "depth {depth} is over the cap"
        );
    }
}

#[cfg(feature = "strict_validate")]
#[test]
fn a_text_pin_is_never_parsed() {
    let payload = b"{\"messages\":[],\"n\":01}";
    let (out, stats) = compress(payload, &Request::pinned(ContentType::Text));
    assert_eq!(out, payload);
    assert_eq!(stats.noop_reason, None);
    assert_eq!(error_of(payload, &Request::default()), ApiError::Malformed);
}
