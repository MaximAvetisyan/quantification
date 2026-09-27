use std::collections::BTreeMap;

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use quantification_core::api::{
    self, Compressor, MarkerStyle, RawOptions, Request as CoreRequest, ScopePolicy, Stats,
};
use quantification_core::config::REQUEST_BODY_LIMIT;
use quantification_server::{CCR_ENABLED, SPAN_PREVIEW_LIMIT, State, app};
use serde_json::Value;
use tower::ServiceExt;

const EXACT_RUN: &[u8] =
    br#"{"messages":[{"role":"user","content":"ERROR timeout\nERROR timeout\nERROR timeout\nERROR done"}]}"#;
const TEMPLATE_RUN: &[u8] = br#"{"messages":[{"role":"user","content":"2024-01-01T00:00:00Z INFO tick\n2024-01-01T00:00:01Z INFO tick\n2024-01-01T00:00:02Z INFO tick\n2024-01-01T00:00:03Z INFO done"}]}"#;
const WS_RUN: &[u8] = br#"{"messages":[{"role":"user","content":"ERROR timeout while connecting to the primary database\nERROR  timeout while connecting to the primary database\nERROR timeout while connecting to the primary database\nERROR done"}]}"#;
const TOOL_SPAN: &[u8] = br#"{"max_tokens":100,"messages":[{"role":"user","content":[{"type":"tool_result","content":"ERROR timeout\nERROR timeout\nERROR timeout\nERROR done"}]}]}"#;
const UNKNOWN: &[u8] = br#"{"foo":1,"bar":[1,2,3]}"#;
const MALFORMED: &[u8] = br#"{"messages":[{"role":"user","content":"unterminated}]}"#;
const PLAIN: &[u8] = b"ERROR timeout\nERROR timeout\nERROR timeout\nERROR done";

const STATS_HEADERS: [&str; 14] = [
    "X-Stats-Bytes-In",
    "X-Stats-Bytes-Out",
    "X-Stats-Approx-Tokens-In",
    "X-Stats-Approx-Tokens-Out",
    "X-Stats-Groups-Collapsed",
    "X-Stats-Exact-Runs",
    "X-Stats-Ws-Runs",
    "X-Stats-Block-Repeats",
    "X-Stats-Template-Groups",
    "X-Stats-Templated-Blocks",
    "X-Stats-Record-Splits",
    "X-Stats-Degraded",
    "X-Stats-Noop-Reason",
    "X-Stats-Algo-Version",
];

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    json: Value,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|value| {
            value
                .to_str()
                .expect("header value is ascii and a valid header name")
        })
    }

    fn stats_headers(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .headers
            .keys()
            .map(|name| name.as_str().to_string())
            .filter(|name| name.starts_with("x-stats-"))
            .collect();
        names.sort();
        names
    }

    fn text(&self) -> String {
        String::from_utf8(self.body.to_vec()).expect("utf8 body")
    }

    fn error_code(&self) -> String {
        self.json["error"]["code"]
            .as_str()
            .expect("error code")
            .to_string()
    }
}

fn router() -> Router {
    app(State::new())
}

async fn send(app: &Router, method: &str, target: &str, body: &[u8]) -> Answer {
    send_with_content_type(app, method, target, body, "application/json").await
}

async fn send_with_content_type(
    app: &Router,
    method: &str,
    target: &str,
    body: &[u8],
    content_type: &str,
) -> Answer {
    let request = Request::builder()
        .method(method)
        .uri(target)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body.to_vec()))
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("router answers");
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json = serde_json::from_slice(&body).unwrap_or(Value::Null);
    Answer {
        status,
        headers,
        body,
        json,
    }
}

async fn compress(app: &Router, target: &str, body: &[u8]) -> Answer {
    send(app, "POST", target, body).await
}

fn core_options(min_group_size: Option<u32>, marker_style: Option<MarkerStyle>) -> CoreRequest {
    CoreRequest::default().with_options(RawOptions {
        scope_policy: Some(ScopePolicy::UserAndTools),
        min_group_size,
        marker_style,
        ..RawOptions::default()
    })
}

fn core(payload: &[u8], request: CoreRequest) -> (Vec<u8>, Stats) {
    let mut compressor = Compressor::new();
    let mut out = Vec::new();
    let stats = compressor
        .compress(payload, &request, &mut out)
        .expect("the core never fails these payloads");
    (out, stats)
}

#[tokio::test]
async fn the_stats_header_names_are_verbatim_and_the_values_are_exact() {
    let answer = compress(&router(), "/v1/compress", EXACT_RUN).await;
    assert_eq!(answer.status, StatusCode::OK);
    let (expected, stats) = core(EXACT_RUN, CoreRequest::default());
    assert_eq!(
        answer.body, expected,
        "the body is the core output byte for byte"
    );
    let mut names: Vec<String> = STATS_HEADERS
        .iter()
        .filter(|name| **name != "X-Stats-Noop-Reason")
        .map(|name| name.to_ascii_lowercase())
        .collect();
    names.sort();
    assert_eq!(
        answer.stats_headers(),
        names,
        "exactly the section 6.1 names"
    );
    for name in STATS_HEADERS {
        assert_eq!(
            answer.header(name).is_some(),
            name != "X-Stats-Noop-Reason",
            "{name} must be reachable under its normative spelling"
        );
    }
    assert_eq!(
        answer.header("X-Stats-Bytes-In"),
        Some(stats.bytes_in.to_string().as_str())
    );
    assert_eq!(
        answer.header("X-Stats-Bytes-Out"),
        Some(expected.len().to_string().as_str())
    );
    assert_eq!(
        answer.header("X-Stats-Bytes-Out"),
        Some(answer.body.len().to_string().as_str())
    );
    assert_eq!(
        answer.header("X-Stats-Approx-Tokens-In"),
        Some((EXACT_RUN.len() as u64 / 4).to_string().as_str())
    );
    assert_eq!(
        answer.header("X-Stats-Approx-Tokens-Out"),
        Some((answer.body.len() as u64 / 4).to_string().as_str())
    );
    assert_eq!(
        answer.header("X-Stats-Groups-Collapsed"),
        Some(stats.groups_collapsed.to_string().as_str())
    );
    assert_eq!(answer.header("X-Stats-Exact-Runs"), Some("1"));
    assert_eq!(answer.header("X-Stats-Ws-Runs"), Some("0"));
    assert_eq!(answer.header("X-Stats-Block-Repeats"), Some("0"));
    assert_eq!(answer.header("X-Stats-Template-Groups"), Some("0"));
    assert_eq!(answer.header("X-Stats-Templated-Blocks"), Some("0"));
    assert_eq!(
        answer.header("X-Stats-Record-Splits"),
        Some(stats.record_splits.to_string().as_str())
    );
    assert_eq!(answer.header("X-Stats-Degraded"), Some("false"));
    assert_eq!(answer.header("X-Stats-Algo-Version"), Some("0.1.0"));
    assert_eq!(
        answer.header("X-Stats-Noop-Reason"),
        None,
        "an absent value is an absent header"
    );
}

#[tokio::test]
async fn the_header_names_are_case_insensitive() {
    let answer = compress(&router(), "/v1/compress", EXACT_RUN).await;
    for name in ["X-Stats-Bytes-In", "x-stats-bytes-in", "X-STATS-BYTES-IN"] {
        assert_eq!(
            answer.header(name),
            Some(EXACT_RUN.len().to_string().as_str()),
            "{name} must reach the same header"
        );
    }
}

#[tokio::test]
async fn envelope_only_never_reach_the_single_compress_headers() {
    let answer = compress(&router(), "/v1/compress", EXACT_RUN).await;
    for name in answer.headers.keys() {
        let name = name.as_str();
        for forbidden in ["timing", "elapsed", "options", "echo", "restore"] {
            assert!(
                !name.contains(forbidden),
                "{name} is envelope-only and must not be a header here"
            );
        }
    }
    assert!(!answer.headers.contains_key("x-stats-options-echo"));
    assert!(!answer.headers.contains_key("x-stats-elapsed-detect-ns"));
    assert!(!answer.headers.contains_key("x-stats-restore-ids"));
}

#[tokio::test]
async fn an_unknown_schema_passes_through_with_a_noop_reason() {
    let answer = compress(&router(), "/v1/compress", UNKNOWN).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body, UNKNOWN, "pass-through is byte identical");
    assert_eq!(answer.header("x-stats-degraded"), Some("true"));
    assert_eq!(answer.header("x-stats-noop-reason"), Some("unknown_schema"));
    assert_eq!(
        answer.header("x-stats-bytes-in"),
        Some(UNKNOWN.len().to_string().as_str())
    );
    assert_eq!(
        answer.header("x-stats-bytes-out"),
        Some(UNKNOWN.len().to_string().as_str())
    );
    assert_eq!(answer.header("x-stats-groups-collapsed"), Some("0"));
}

#[tokio::test]
async fn a_malformed_document_passes_through_too() {
    let answer = compress(&router(), "/v1/compress", MALFORMED).await;
    if api::STRICT_VALIDATE {
        assert_eq!(answer.status, StatusCode::BAD_REQUEST);
        assert_eq!(answer.error_code(), "malformed");
        return;
    }
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body, MALFORMED);
    assert_eq!(answer.header("x-stats-degraded"), Some("true"));
    assert_eq!(answer.header("x-stats-noop-reason"), Some("malformed"));
}

#[tokio::test]
async fn an_empty_payload_is_a_pass_through_not_a_failure() {
    for payload in [&b""[..], &b"   "[..], &b"null"[..], &b"{}"[..], &b"[]"[..]] {
        let answer = compress(&router(), "/v1/compress", payload).await;
        assert_eq!(answer.status, StatusCode::OK);
        assert_eq!(answer.body, payload);
    }
}

#[tokio::test]
async fn the_detectors_are_reachable_through_their_options() {
    let exact = compress(&router(), "/v1/compress", EXACT_RUN).await;
    assert_eq!(exact.header("x-stats-exact-runs"), Some("1"));
    assert_eq!(exact.body, core(EXACT_RUN, CoreRequest::default()).0);
    assert!(
        exact.text().contains("[... x2 identical"),
        "an all-ascii span takes the ascii fallback"
    );
    let ascii = compress(&router(), "/v1/compress?marker_style=ascii", EXACT_RUN).await;
    assert!(ascii.text().contains("[... x2 identical"));
    let unicode = compress(&router(), "/v1/compress?marker_style=unicode", EXACT_RUN).await;
    assert!(unicode.text().contains("\u{27ea}\u{d7}2 identical"));
    let templated = compress(&router(), "/v1/compress", TEMPLATE_RUN).await;
    assert_eq!(templated.header("x-stats-template-groups"), Some("1"));
    assert!(templated.text().contains("rows, template"));
    let without = compress(&router(), "/v1/compress?template_dedup=false", TEMPLATE_RUN).await;
    assert_eq!(without.header("x-stats-template-groups"), Some("0"));
    assert_eq!(without.body, TEMPLATE_RUN);
    let ws = compress(&router(), "/v1/compress", WS_RUN).await;
    assert_eq!(ws.header("x-stats-ws-runs"), Some("1"));
    assert!(ws.text().contains("rows, ws-equal"));
    let raw = compress(&router(), "/v1/compress?normalize_ws=false", WS_RUN).await;
    assert_eq!(raw.header("x-stats-ws-runs"), Some("0"));
    assert!(!raw.text().contains("rows, ws-equal"));
    assert_eq!(
        raw.header("x-stats-template-groups"),
        Some("1"),
        "the mask finds what the ws domain lost"
    );
}

#[tokio::test]
async fn the_scope_policy_selects_the_spans() {
    let default = compress(&router(), "/v1/compress", TOOL_SPAN).await;
    assert_eq!(
        default.body, TOOL_SPAN,
        "a tool span is out of user_content scope"
    );
    assert_eq!(default.header("x-stats-degraded"), Some("false"));
    let tools = compress(
        &router(),
        "/v1/compress?scope_policy=user_and_tools",
        TOOL_SPAN,
    )
    .await;
    assert!(tools.body.len() < TOOL_SPAN.len());
    assert!(tools.text().contains("identical"));
}

#[tokio::test]
async fn a_pinned_content_type_contradiction_is_422_and_a_matching_pin_is_200() {
    let contradicted = compress(&router(), "/v1/compress?content_type=responses", EXACT_RUN).await;
    assert_eq!(contradicted.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(contradicted.error_code(), "content_type_mismatch");
    let pinned = compress(&router(), "/v1/compress?content_type=chat", EXACT_RUN).await;
    assert_eq!(pinned.status, StatusCode::OK);
    assert_eq!(
        pinned.body,
        compress(&router(), "/v1/compress", EXACT_RUN).await.body
    );
    let unknown_under_text = compress(&router(), "/v1/compress?content_type=text", UNKNOWN).await;
    assert_eq!(unknown_under_text.status, StatusCode::OK);
    assert_eq!(unknown_under_text.body, UNKNOWN);
    assert_eq!(unknown_under_text.header("x-stats-degraded"), Some("false"));
    let malformed_under_text =
        compress(&router(), "/v1/compress?content_type=text", MALFORMED).await;
    assert_eq!(malformed_under_text.status, StatusCode::OK);
}

#[tokio::test]
async fn every_invalid_option_is_a_400() {
    for (target, expected) in [
        ("/v1/compress?min_group_size=1", "below"),
        ("/v1/compress?min_group_size=abc", "min_group_size"),
        ("/v1/compress?min_group_size=-2", "min_group_size"),
        ("/v1/compress?scope_policy=all_messages", "reserved"),
        ("/v1/compress?scope_policy=explicit_paths", "reserved"),
        ("/v1/compress?scope_policy=everyone", "scope_policy"),
        ("/v1/compress?normalize_ws=1", "true or false"),
        ("/v1/compress?normalize_ws=yes", "true or false"),
        ("/v1/compress?marker_style=zzz", "marker_style"),
        ("/v1/compress?content_type=xml", "content_type"),
        ("/v1/compress?nope=1", "unknown query parameter"),
        ("/v1/compress?envelope=xml", "envelope"),
        (
            "/v1/compress?envelope=json&min_group_size=5",
            "envelope body",
        ),
    ] {
        let answer = compress(&router(), target, EXACT_RUN).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{target}");
        assert!(
            matches!(
                answer.error_code().as_str(),
                "invalid_argument" | "invalid_options"
            ),
            "{target} must carry a 400 error code, got {}",
            answer.error_code()
        );
        assert!(
            answer.json["error"]["message"]
                .as_str()
                .expect("message")
                .contains(expected),
            "{target} must explain itself: {}",
            answer.json["error"]["message"]
        );
    }
}

#[tokio::test]
async fn a_broken_envelope_is_a_400() {
    for (body, expected) in [
        (&b"{"[..], "envelope"),
        (&br#"{"paylaod":"hi"}"#[..], "envelope"),
        (&br#"{"payload":7}"#[..], "envelope"),
        (
            &br#"{"payload":"hi","options":{"min_group_size":-1}}"#[..],
            "envelope",
        ),
        (
            &br#"{"payload":"hi","options":{"marker_style":"zzz"}}"#[..],
            "marker_style",
        ),
        (
            &br#"{"payload":"hi","options":{"nope":true}}"#[..],
            "envelope",
        ),
        (
            &br#"{"payload":"hi","content_type":"xml"}"#[..],
            "content_type",
        ),
        (
            &br#"{"payload":"hi","options":{"scope_policy":"all_messages"}}"#[..],
            "reserved",
        ),
    ] {
        let answer = compress(&router(), "/v1/compress?envelope=json", body).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{expected}");
        assert!(
            answer.json["error"]["message"]
                .as_str()
                .expect("message")
                .contains(expected),
            "the message must mention {expected}"
        );
    }
}

#[tokio::test]
async fn the_envelope_returns_the_payload_and_structured_stats() {
    let envelope = serde_json::json!({
        "payload": String::from_utf8(TEMPLATE_RUN.to_vec()).expect("utf8"),
        "content_type": "chat",
        "options": {"scope_policy": "user_and_tools", "min_group_size": 4, "marker_style": "ascii"},
    });
    let answer = compress(
        &router(),
        "/v1/compress?envelope=json",
        &serde_json::to_vec(&envelope).expect("json"),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.header("content-type"), Some("application/json"));
    assert_eq!(
        answer.stats_headers(),
        Vec::<String>::new(),
        "envelope stats ride in the body"
    );
    let (expected, stats) = core(
        TEMPLATE_RUN,
        core_options(Some(4), Some(MarkerStyle::Ascii)),
    );
    assert_eq!(
        answer.json["payload"].as_str().expect("payload"),
        String::from_utf8_lossy(&expected)
    );
    let served = &answer.json["stats"];
    for field in [
        "bytes_in",
        "bytes_out",
        "approx_tokens_in",
        "approx_tokens_out",
        "groups_collapsed",
        "exact_runs",
        "ws_runs",
        "block_repeats",
        "template_groups",
        "degraded",
        "noop_reason",
        "elapsed_detect_ns",
        "elapsed_compact_ns",
        "elapsed_splice_ns",
        "algo_version",
        "templated_blocks",
        "options_echo",
        "record_splits",
    ] {
        assert!(served.get(field).is_some(), "stats.{field} must be present");
    }
    assert_eq!(served["bytes_in"], stats.bytes_in);
    assert_eq!(served["bytes_out"], expected.len() as u64);
    assert_eq!(served["degraded"], false);
    assert_eq!(served["noop_reason"], Value::Null);
    assert_eq!(served["algo_version"], "0.1.0");
    assert_eq!(
        served["options_echo"],
        "{\"scope_policy\":\"user_and_tools\",\"min_group_size\":4,\"normalize_ws\":true,\"template_dedup\":true,\"marker_style\":\"ascii\",\"reversible\":false}"
    );
    assert!(served["elapsed_detect_ns"].is_u64());
}

#[tokio::test]
async fn the_envelope_reports_a_degraded_pass_through() {
    let envelope =
        serde_json::json!({"payload": String::from_utf8(UNKNOWN.to_vec()).expect("utf8")});
    let answer = compress(
        &router(),
        "/v1/compress?envelope=json",
        &serde_json::to_vec(&envelope).expect("json"),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.json["stats"]["degraded"], true);
    assert_eq!(answer.json["stats"]["noop_reason"], "unknown_schema");
    assert_eq!(
        answer.json["payload"],
        serde_json::json!(String::from_utf8_lossy(UNKNOWN))
    );
}

#[tokio::test]
async fn the_default_options_echo_is_the_section_seven_default() {
    let envelope = serde_json::json!({"payload": "hi"});
    let answer = compress(
        &router(),
        "/v1/compress?envelope=json",
        &serde_json::to_vec(&envelope).expect("json"),
    )
    .await;
    assert_eq!(
        answer.json["stats"]["options_echo"],
        "{\"scope_policy\":\"user_content\",\"min_group_size\":3,\"normalize_ws\":true,\"template_dedup\":true,\"marker_style\":\"auto\",\"reversible\":false}"
    );
}

#[tokio::test]
async fn reversible_true_is_refused_and_reversible_false_resolves() {
    let envelope = |reversible: bool| {
        serde_json::to_vec(&serde_json::json!({
            "payload": String::from_utf8(EXACT_RUN.to_vec()).expect("utf8"),
            "options": {"reversible": reversible},
        }))
        .expect("json")
    };
    let target = "/v1/compress?reversible=true";
    let answer = compress(&router(), target, EXACT_RUN).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{target}");
    assert_eq!(answer.error_code(), "invalid_options", "{target}");
    assert!(
        answer.json["error"]["message"]
            .as_str()
            .expect("message")
            .contains("reversible=true is not accepted"),
        "{target}"
    );
    let answer = compress(&router(), "/v1/compress?envelope=json", &envelope(true)).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(answer.error_code(), "invalid_options");
    assert_eq!(
        answer.json.get("stats"),
        None,
        "a refused option answers no stats and no ids"
    );

    let plain = compress(&router(), "/v1/compress", EXACT_RUN).await;
    let off = compress(&router(), "/v1/compress?reversible=false", EXACT_RUN).await;
    assert_eq!(off.status, StatusCode::OK);
    assert_eq!(off.body, plain.body, "false changes no output byte");
    let answer = compress(&router(), "/v1/compress?envelope=json", &envelope(false)).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert!(
        answer.json["stats"]["options_echo"]
            .as_str()
            .expect("echo")
            .ends_with("\"reversible\":false}")
    );
    assert_eq!(
        answer.json["stats"].get("restore_ids"),
        None,
        "no store, so no ids"
    );
}

#[tokio::test]
async fn a_body_over_sixty_four_mebibytes_is_413() {
    let app = router();
    let answer = compress(&app, "/v1/compress", &vec![b'x'; REQUEST_BODY_LIMIT + 1]).await;
    assert_eq!(answer.status, StatusCode::PAYLOAD_TOO_LARGE);
    let answer = compress(&app, "/v1/detect", &vec![b'x'; REQUEST_BODY_LIMIT + 1]).await;
    assert_eq!(answer.status, StatusCode::PAYLOAD_TOO_LARGE);
    let answer = compress(
        &app,
        "/v1/compress?envelope=json",
        &vec![b'x'; REQUEST_BODY_LIMIT + 1],
    )
    .await;
    assert_eq!(answer.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn a_body_over_the_axum_default_but_under_the_limit_is_accepted() {
    let filler = "a".repeat(3 * 1024 * 1024);
    let payload = format!(r#"{{"messages":[{{"role":"user","content":"{filler}"}}]}}"#);
    let answer = compress(&router(), "/v1/compress", payload.as_bytes()).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(
        answer.header("x-stats-bytes-in"),
        Some(payload.len().to_string().as_str())
    );
    assert_eq!(answer.body, payload.as_bytes());
}

#[tokio::test]
async fn the_response_echoes_the_request_content_type() {
    let answer = send_with_content_type(
        &router(),
        "POST",
        "/v1/compress",
        EXACT_RUN,
        "application/json; charset=utf-8",
    )
    .await;
    assert_eq!(
        answer.header("content-type"),
        Some("application/json; charset=utf-8")
    );
    let answer =
        send_with_content_type(&router(), "POST", "/v1/compress", PLAIN, "text/plain").await;
    assert_eq!(answer.header("content-type"), Some("text/plain"));
    let answer = compress(&router(), "/v1/compress", PLAIN).await;
    assert_eq!(answer.header("content-type"), Some("application/json"));
    assert_eq!(
        answer.body, PLAIN,
        "three identical lines are not profitable in text"
    );
}

#[tokio::test]
async fn identical_requests_answer_with_identical_bytes() {
    let app = router();
    let first = compress(&app, "/v1/compress?min_group_size=2", TEMPLATE_RUN).await;
    for _ in 0..7 {
        let again = compress(&app, "/v1/compress?min_group_size=2", TEMPLATE_RUN).await;
        assert_eq!(again.status, first.status);
        assert_eq!(again.headers, first.headers, "headers carry no timing");
        assert_eq!(again.body, first.body);
    }
    let (_, stats) = core(TEMPLATE_RUN, CoreRequest::default());
    assert_eq!(
        first.header("x-stats-bytes-in"),
        Some(stats.bytes_in.to_string().as_str())
    );
}

#[tokio::test]
async fn detect_reports_the_schema_and_a_span_preview() {
    let answer = send(&router(), "POST", "/v1/detect", EXACT_RUN).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.header("content-type"), Some("application/json"));
    assert_eq!(answer.json["schema"], "chat");
    assert_eq!(answer.json["degraded"], false);
    assert_eq!(answer.json["noop_reason"], Value::Null);
    assert_eq!(answer.json["scope_policy"], "user_content");
    assert_eq!(answer.json["span_count"], 1);
    assert_eq!(answer.json["spans_truncated"], false);
    let span = &answer.json["spans"][0];
    assert_eq!(span["class"], "user");
    let needle = br#"ERROR timeout\nERROR timeout\nERROR timeout\nERROR done"#;
    let start = EXACT_RUN
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("the content interior");
    assert_eq!(span["start"], start);
    assert_eq!(span["end"], start + needle.len());
    assert_eq!(&EXACT_RUN[start..start + needle.len()], needle);

    let answer = send(&router(), "POST", "/v1/detect", UNKNOWN).await;
    assert_eq!(answer.json["schema"], Value::Null);
    assert_eq!(answer.json["degraded"], true);
    assert_eq!(answer.json["noop_reason"], "unknown_schema");
    assert_eq!(answer.json["span_count"], 0);

    let answer = send(
        &router(),
        "POST",
        "/v1/detect?scope_policy=user_and_tools",
        TOOL_SPAN,
    )
    .await;
    assert_eq!(answer.json["schema"], "messages");
    assert_eq!(answer.json["spans"][0]["class"], "tool");
    let answer = send(
        &router(),
        "POST",
        "/v1/detect?scope_policy=user_content",
        TOOL_SPAN,
    )
    .await;
    assert_eq!(answer.json["span_count"], 0);
    let answer = send(
        &router(),
        "POST",
        "/v1/detect?scope_policy=all_messages",
        TOOL_SPAN,
    )
    .await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    let answer = send(&router(), "POST", "/v1/detect?min_group_size=3", TOOL_SPAN).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    let answer = send(&router(), "POST", "/v1/detect", PLAIN).await;
    assert_eq!(answer.json["schema"], "text");
    assert_eq!(answer.json["span_count"], 1);
}

#[tokio::test]
async fn a_long_span_list_is_previewed_not_dumped() {
    let messages: Vec<String> = (0..SPAN_PREVIEW_LIMIT + 5)
        .map(|at| format!(r#"{{"role":"user","content":"line {at}"}}"#))
        .collect();
    let payload = format!(r#"{{"messages":[{}]}}"#, messages.join(","));
    let answer = send(&router(), "POST", "/v1/detect", payload.as_bytes()).await;
    assert_eq!(answer.json["span_count"], SPAN_PREVIEW_LIMIT + 5);
    assert_eq!(answer.json["spans_truncated"], true);
    assert_eq!(
        answer.json["spans"].as_array().expect("spans").len(),
        SPAN_PREVIEW_LIMIT
    );
    assert_eq!(answer.json["spans"][0]["class"], "user");
}

#[tokio::test]
async fn restore_is_flag_gated_and_never_guesses() {
    let answer = send(&router(), "POST", "/v1/restore", b"{}").await;
    assert_eq!(answer.status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(answer.error_code(), "not_implemented");
    assert_eq!(answer.header("content-type"), Some("application/json"));
    let message = answer.json["error"]["message"].as_str().expect("message");
    let expected = if CCR_ENABLED {
        "not implemented"
    } else {
        "disabled"
    };
    assert!(message.contains(expected), "{message} must say {expected}");
}

#[tokio::test]
async fn the_ops_endpoints_answer() {
    let app = router();
    let healthz = send(&app, "GET", "/healthz", b"").await;
    assert_eq!(healthz.status, StatusCode::OK);
    assert_eq!(healthz.json["status"], "ok");
    let readyz = send(&app, "GET", "/readyz", b"").await;
    assert_eq!(readyz.status, StatusCode::OK);
    assert_eq!(readyz.json["status"], "ready");

    assert_eq!(
        compress(&app, "/v1/compress", UNKNOWN).await.status,
        StatusCode::OK
    );
    assert_eq!(
        compress(&app, "/v1/compress?min_group_size=1", UNKNOWN)
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let metrics = send(&app, "GET", "/metrics", b"").await;
    assert_eq!(metrics.status, StatusCode::OK);
    assert_eq!(
        metrics.header("content-type"),
        Some("text/plain; version=0.0.4; charset=utf-8")
    );
    let text = metrics.text();
    assert!(text.contains(
        "# HELP quantification_http_requests_total Requests served, by route and status.\n"
    ));
    assert!(text.contains("# TYPE quantification_http_requests_total counter\n"));
    assert!(
        text.contains(
            "quantification_http_requests_total{route=\"/v1/compress\",status=\"200\"} 1\n"
        )
    );
    assert!(
        text.contains(
            "quantification_http_requests_total{route=\"/v1/compress\",status=\"400\"} 1\n"
        )
    );
    assert!(text.contains(&format!(
        "quantification_payload_bytes_total{{direction=\"in\"}} {}\n",
        UNKNOWN.len()
    )));
    assert!(text.contains("quantification_pass_through_total 1\n"));
    assert!(text.contains(&format!(
        "quantification_build_info{{algo_version=\"0.1.0\",ccr=\"{CCR_ENABLED}\"}} 1\n"
    )));
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        assert!(line.contains(' '), "a sample line needs a value: {line}");
    }
}

#[tokio::test]
async fn an_unknown_route_is_a_404_and_a_wrong_method_is_a_405() {
    let app = router();
    assert_eq!(
        send(&app, "POST", "/v1/nope", b"").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(&app, "GET", "/v1/compress", b"").await.status,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn the_wire_format_is_a_real_http_response() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router()).await;
    });

    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    let head = format!(
        "POST /v1/compress HTTP/1.1\r\nhost: {address}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        EXACT_RUN.len()
    );
    stream.write_all(head.as_bytes()).await.expect("head");
    stream.write_all(EXACT_RUN).await.expect("body");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read");
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = raw.split_once("\r\n\r\n").expect("head and body");
    let (status, headers) = head.split_once("\r\n").expect("status line");

    assert_eq!(status, "HTTP/1.1 200 OK");
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for line in headers.lines().skip(1) {
        let (name, value) = line.split_once(": ").expect("header line");
        seen.insert(name.to_ascii_lowercase(), value.to_string());
    }
    assert_eq!(
        seen.get("x-stats-bytes-in").map(String::as_str),
        Some(EXACT_RUN.len().to_string().as_str())
    );
    assert_eq!(
        seen.get("x-stats-degraded").map(String::as_str),
        Some("false")
    );
    assert!(head.contains("\r\nx-stats-algo-version: 0.1.0\r\n"));
    assert!(
        head.to_ascii_lowercase()
            .contains("x-stats-approx-tokens-out")
    );
    assert!(
        head.to_ascii_lowercase()
            .contains("x-stats-templated-blocks")
    );
    assert_eq!(
        body,
        String::from_utf8_lossy(&core(EXACT_RUN, CoreRequest::default()).0)
    );
    assert_eq!(
        seen.get("content-length").map(String::as_str),
        Some(body.len().to_string().as_str())
    );
}
