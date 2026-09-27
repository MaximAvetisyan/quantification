use std::sync::Arc;

use axum::body::{Body, Bytes, to_bytes};
use axum::http::Request as HttpRequest;
use prost::Message;
use quantification_core::api::{self, Compressor, Request as CoreRequest, Stats};
use quantification_core::config::REQUEST_BODY_LIMIT;
use quantification_proto::compressor::v1::compressor_client::CompressorClient;
use quantification_proto::compressor::v1::{
    CompressRequest, CompressResponse, ContentType, MarkerStyle as WireMarkerStyle, Options,
    RestoreRequest, ScopePolicy as WireScopePolicy, Stats as GrpcStats,
};
use quantification_server::grpc::{self, RestoreStore};
use quantification_server::{CCR_ENABLED, State, app};
use serde_json::Value;
use tonic::service::Routes;
use tonic::{Code, Status};
use tower::{Service, ServiceExt};

const EXACT_RUN: &[u8] =
    br#"{"messages":[{"role":"user","content":"ERROR timeout\nERROR timeout\nERROR timeout\nERROR done"}]}"#;
const TEMPLATE_RUN: &[u8] = br#"{"messages":[{"role":"user","content":"2024-01-01T00:00:00Z INFO tick\n2024-01-01T00:00:01Z INFO tick\n2024-01-01T00:00:02Z INFO tick\n2024-01-01T00:00:03Z INFO done"}]}"#;
const WS_RUN: &[u8] = br#"{"messages":[{"role":"user","content":"ERROR timeout while connecting to the primary database\nERROR  timeout while connecting to the primary database\nERROR timeout while connecting to the primary database\nERROR done"}]}"#;
const TOOL_SPAN: &[u8] = br#"{"max_tokens":100,"messages":[{"role":"user","content":[{"type":"tool_result","content":"ERROR timeout\nERROR timeout\nERROR timeout\nERROR done"}]}]}"#;
const RESPONSES: &[u8] = br#"{"input":[{"role":"user","content":"ERROR timeout\nERROR timeout\nERROR timeout\nERROR done"}]}"#;
const UNKNOWN: &[u8] = br#"{"foo":1,"bar":[1,2,3]}"#;
const MALFORMED: &[u8] = br#"{"messages":[{"role":"user","content":"unterminated}]}"#;
const PLAIN: &[u8] = b"ERROR timeout\nERROR timeout\nERROR timeout\nERROR done";

const SERVICE: &str = "compressor.v1.Compressor";

struct Case {
    name: &'static str,
    payload: &'static [u8],
    query: &'static str,
    content_type: i32,
    scope_policy: i32,
    options: Options,
}

fn case(
    name: &'static str,
    payload: &'static [u8],
    query: &'static str,
    content_type: ContentType,
    scope_policy: WireScopePolicy,
    options: Options,
) -> Case {
    Case {
        name,
        payload,
        query,
        content_type: content_type as i32,
        scope_policy: scope_policy as i32,
        options,
    }
}

fn cases() -> Vec<Case> {
    let mut cases = vec![
        case(
            "the defaults on an exact run",
            EXACT_RUN,
            "",
            ContentType::Auto,
            WireScopePolicy::UserContent,
            Options::default(),
        ),
        case(
            "a template group",
            TEMPLATE_RUN,
            "",
            ContentType::Auto,
            WireScopePolicy::UserContent,
            Options::default(),
        ),
        case(
            "normalize_ws=false",
            WS_RUN,
            "?normalize_ws=false",
            ContentType::Auto,
            WireScopePolicy::UserContent,
            Options {
                normalize_ws: Some(false),
                ..Options::default()
            },
        ),
        case(
            "template_dedup=false",
            TEMPLATE_RUN,
            "?template_dedup=false",
            ContentType::Auto,
            WireScopePolicy::UserContent,
            Options {
                template_dedup: Some(false),
                ..Options::default()
            },
        ),
        case(
            "user_and_tools over a tool_result block",
            TOOL_SPAN,
            "?scope_policy=user_and_tools",
            ContentType::Auto,
            WireScopePolicy::UserAndTools,
            Options::default(),
        ),
        case(
            "user_content leaves a tool_result block alone",
            TOOL_SPAN,
            "?content_type=messages",
            ContentType::Messages,
            WireScopePolicy::UserContent,
            Options::default(),
        ),
        case(
            "an ascii marker",
            EXACT_RUN,
            "?marker_style=ascii",
            ContentType::Auto,
            WireScopePolicy::UserContent,
            Options {
                marker_style: WireMarkerStyle::Ascii as i32,
                ..Options::default()
            },
        ),
        case(
            "a unicode marker under a chat pin",
            EXACT_RUN,
            "?marker_style=unicode&content_type=chat",
            ContentType::Chat,
            WireScopePolicy::UserContent,
            Options {
                marker_style: WireMarkerStyle::Unicode as i32,
                ..Options::default()
            },
        ),
        case(
            "min_group_size=2",
            TEMPLATE_RUN,
            "?min_group_size=2",
            ContentType::Auto,
            WireScopePolicy::UserContent,
            Options {
                min_group_size: 2,
                ..Options::default()
            },
        ),
        case(
            "the responses schema",
            RESPONSES,
            "?content_type=responses",
            ContentType::Responses,
            WireScopePolicy::UserContent,
            Options::default(),
        ),
        case(
            "plain text under a text pin",
            PLAIN,
            "?content_type=text",
            ContentType::Text,
            WireScopePolicy::UserContent,
            Options::default(),
        ),
        case(
            "an unknown schema degrades",
            UNKNOWN,
            "",
            ContentType::Auto,
            WireScopePolicy::UserContent,
            Options::default(),
        ),
        case(
            "an absent options message is the section seven default",
            EXACT_RUN,
            "",
            ContentType::Auto,
            WireScopePolicy::UserContent,
            Options::default(),
        ),
    ];
    if !api::STRICT_VALIDATE {
        cases.push(case(
            "a malformed document degrades",
            MALFORMED,
            "",
            ContentType::Auto,
            WireScopePolicy::UserContent,
            Options::default(),
        ));
    }
    cases
}

fn client() -> CompressorClient<Routes> {
    CompressorClient::new(grpc::routes(grpc::Service::new()))
        .max_decoding_message_size(REQUEST_BODY_LIMIT)
}

fn request(case: &Case) -> CompressRequest {
    CompressRequest {
        payload: case.payload.to_vec(),
        content_type: case.content_type,
        scope_policy: case.scope_policy,
        options: Some(case.options),
    }
}

async fn compress(request: CompressRequest) -> Result<CompressResponse, Status> {
    client()
        .compress(request)
        .await
        .map(|answer| answer.into_inner())
}

fn core(payload: &[u8], request: CoreRequest) -> (Vec<u8>, Stats) {
    let mut compressor = Compressor::new();
    let mut out = Vec::new();
    let stats = compressor
        .compress(payload, &request, &mut out)
        .expect("the core never refuses these payloads");
    (out, stats)
}

fn core_request(case: &Case) -> CoreRequest {
    CoreRequest::default().with_options(quantification_proto::convert::to_raw_options(&request(
        case,
    )))
}

async fn http_bytes(target: &str, payload: &[u8]) -> Bytes {
    let (status, body) = http_status_and_bytes(target, payload).await;
    assert_eq!(status, 200, "{target} must succeed");
    body
}

async fn http_status_and_bytes(target: &str, payload: &[u8]) -> (u16, Bytes) {
    let request = HttpRequest::builder()
        .method("POST")
        .uri(target)
        .body(Body::from(payload.to_vec()))
        .expect("request");
    let response = app(State::new()).oneshot(request).await.expect("served");
    let status = response.status().as_u16();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, body)
}

fn content_type_name(value: i32) -> Option<&'static str> {
    match value {
        value if value == ContentType::Auto as i32 => None,
        value if value == ContentType::Chat as i32 => Some("chat"),
        value if value == ContentType::Responses as i32 => Some("responses"),
        value if value == ContentType::Messages as i32 => Some("messages"),
        value if value == ContentType::Text as i32 => Some("text"),
        _ => panic!("{value} is not a content type"),
    }
}

fn marker_style_name(value: i32) -> &'static str {
    match value {
        value if value == WireMarkerStyle::Auto as i32 => "auto",
        value if value == WireMarkerStyle::Ascii as i32 => "ascii",
        value if value == WireMarkerStyle::Unicode as i32 => "unicode",
        _ => panic!("{value} is not a marker style"),
    }
}

fn scope_policy_name(value: i32) -> &'static str {
    match value {
        value if value == WireScopePolicy::UserContent as i32 => "user_content",
        value if value == WireScopePolicy::UserAndTools as i32 => "user_and_tools",
        _ => panic!("{value} is not an implemented scope policy"),
    }
}

fn envelope_body(case: &Case) -> String {
    let mut envelope = serde_json::Map::new();
    envelope.insert(
        "payload".to_string(),
        Value::String(String::from_utf8_lossy(case.payload).into_owned()),
    );
    if let Some(name) = content_type_name(case.content_type) {
        envelope.insert("content_type".to_string(), Value::String(name.to_string()));
    }
    let mut options = serde_json::Map::new();
    if case.options.min_group_size > 0 {
        options.insert(
            "min_group_size".to_string(),
            Value::from(case.options.min_group_size),
        );
    }
    for (name, flag) in [
        ("normalize_ws", case.options.normalize_ws),
        ("template_dedup", case.options.template_dedup),
        ("reversible", case.options.reversible),
    ] {
        if let Some(flag) = flag {
            options.insert(name.to_string(), Value::Bool(flag));
        }
    }
    if case.options.marker_style != WireMarkerStyle::Auto as i32 {
        options.insert(
            "marker_style".to_string(),
            Value::String(marker_style_name(case.options.marker_style).to_string()),
        );
    }
    options.insert(
        "scope_policy".to_string(),
        Value::String(scope_policy_name(case.scope_policy).to_string()),
    );
    if !options.is_empty() {
        envelope.insert("options".to_string(), Value::Object(options));
    }
    Value::Object(envelope).to_string()
}

async fn http_envelope(case: &Case) -> Value {
    let bytes = http_bytes("/v1/compress?envelope=json", envelope_body(case).as_bytes()).await;
    serde_json::from_slice(&bytes).expect("envelope json")
}

fn assert_same_stats(served: &GrpcStats, http: &Value, name: &str) {
    let http_reason = match &http["noop_reason"] {
        Value::Null => String::new(),
        Value::String(reason) => reason.clone(),
        other => panic!("{name}: http noop_reason {other}"),
    };
    assert_eq!(
        served.bytes_in,
        http["bytes_in"].as_u64().expect(name),
        "{name}"
    );
    assert_eq!(
        served.bytes_out,
        http["bytes_out"].as_u64().expect(name),
        "{name}"
    );
    assert_eq!(
        served.approx_tokens_in,
        http["approx_tokens_in"].as_u64().expect(name),
        "{name}"
    );
    assert_eq!(
        served.approx_tokens_out,
        http["approx_tokens_out"].as_u64().expect(name),
        "{name}"
    );
    assert_eq!(
        served.groups_collapsed,
        http["groups_collapsed"].as_u64().expect(name),
        "{name}"
    );
    assert_eq!(
        served.exact_runs,
        http["exact_runs"].as_u64().expect(name),
        "{name}"
    );
    assert_eq!(
        served.ws_runs,
        http["ws_runs"].as_u64().expect(name),
        "{name}"
    );
    assert_eq!(
        served.block_repeats,
        http["block_repeats"].as_u64().expect(name),
        "{name}"
    );
    assert_eq!(
        served.template_groups,
        http["template_groups"].as_u64().expect(name),
        "{name}"
    );
    assert_eq!(
        served.templated_blocks,
        http["templated_blocks"].as_u64().expect(name),
        "{name}"
    );
    assert_eq!(
        served.record_splits,
        http["record_splits"].as_u64().expect(name),
        "{name}"
    );
    assert_eq!(
        served.degraded,
        http["degraded"].as_bool().expect(name),
        "{name}"
    );
    assert_eq!(served.noop_reason, http_reason, "{name}");
    assert_eq!(served.algo_version, "0.1.0", "{name}");
    assert_eq!(
        served.options_echo,
        http["options_echo"].as_str().expect(name),
        "{name}"
    );
    assert!(
        served.restore_ids.is_empty(),
        "{name}: the reversible store is W3.4's, so there are no ids"
    );
}

#[tokio::test]
async fn every_case_answers_the_core_bytes_and_a_full_stats_message() {
    for case in cases() {
        let answer = compress(request(&case)).await.expect(case.name);
        let (expected, stats) = core(case.payload, core_request(&case));
        assert_eq!(
            answer.payload, expected,
            "{}: the payload is the core output byte for byte",
            case.name
        );
        let served = answer.stats.expect(case.name);
        assert_eq!(served.bytes_in, stats.bytes_in, "{}", case.name);
        assert_eq!(served.bytes_out, expected.len() as u64, "{}", case.name);
        assert_eq!(
            served.approx_tokens_in,
            case.payload.len() as u64 / 4,
            "{}",
            case.name
        );
        assert_eq!(
            served.approx_tokens_out,
            expected.len() as u64 / 4,
            "{}",
            case.name
        );
        assert_eq!(
            served.groups_collapsed, stats.groups_collapsed,
            "{}",
            case.name
        );
        assert_eq!(served.exact_runs, stats.exact_runs, "{}", case.name);
        assert_eq!(served.ws_runs, stats.ws_runs, "{}", case.name);
        assert_eq!(served.block_repeats, stats.block_repeats, "{}", case.name);
        assert_eq!(
            served.template_groups, stats.template_groups,
            "{}",
            case.name
        );
        assert_eq!(
            served.templated_blocks, stats.templated_blocks,
            "{}",
            case.name
        );
        assert_eq!(served.record_splits, stats.record_splits, "{}", case.name);
        assert_eq!(served.degraded, stats.degraded, "{}", case.name);
        assert_eq!(
            served.noop_reason,
            stats
                .noop_reason
                .map_or_else(String::new, |reason| reason.as_str().to_string()),
            "{}",
            case.name
        );
        assert_eq!(served.algo_version, api::ALGO_VERSION, "{}", case.name);
        assert_eq!(served.options_echo, stats.options_echo, "{}", case.name);
        assert!(served.restore_ids.is_empty(), "{}", case.name);
        assert!(
            served.elapsed_detect_ns + served.elapsed_compact_ns + served.elapsed_splice_ns
                < 60_000_000_000,
            "{}: the three timings are real measurements",
            case.name
        );
    }
}

#[tokio::test]
async fn the_detectors_are_reachable_through_their_options() {
    let answer = compress(request(&cases()[0])).await.expect("compress");
    let stats = answer.stats.expect("stats");
    assert_eq!(stats.exact_runs, 1);
    assert_eq!(stats.ws_runs, 0);
    assert_eq!(stats.groups_collapsed, 1);
    assert!(!stats.degraded);
    let answer = compress(request(&cases()[1])).await.expect("compress");
    assert_eq!(answer.stats.expect("stats").template_groups, 1);
    let answer = compress(request(&cases()[2])).await.expect("compress");
    let stats = answer.stats.expect("stats");
    assert_eq!(stats.ws_runs, 0);
    assert_eq!(stats.template_groups, 1);
    let answer = compress(request(&cases()[3])).await.expect("compress");
    let stats = answer.stats.expect("stats");
    assert_eq!(stats.template_groups, 0);
    assert_eq!(answer.payload, TEMPLATE_RUN);
    let answer = compress(request(&cases()[4])).await.expect("compress");
    assert!(answer.payload.len() < TOOL_SPAN.len());
    let answer = compress(request(&cases()[5])).await.expect("compress");
    assert_eq!(answer.payload, TOOL_SPAN);
    let answer = compress(request(&cases()[6])).await.expect("compress");
    assert!(String::from_utf8_lossy(&answer.payload).contains("[... x2 identical"));
    let answer = compress(request(&cases()[7])).await.expect("compress");
    assert!(String::from_utf8_lossy(&answer.payload).contains("\u{27ea}\u{d7}2 identical"));
}

#[tokio::test]
async fn http_and_grpc_answer_with_identical_bytes_and_stats() {
    for case in cases() {
        let answer = compress(request(&case)).await.expect(case.name);
        let http = http_bytes(&format!("/v1/compress{}", case.query), case.payload).await;
        assert_eq!(
            http.as_ref(),
            answer.payload.as_slice(),
            "{}: http and grpc must return the same bytes",
            case.name
        );
        let envelope = http_envelope(&case).await;
        assert_eq!(
            envelope["payload"].as_str().expect(case.name),
            String::from_utf8_lossy(&answer.payload),
            "{}",
            case.name
        );
        assert_same_stats(
            answer.stats.as_ref().expect(case.name),
            &envelope["stats"],
            case.name,
        );
    }
}

#[tokio::test]
async fn omitted_options_take_the_defaults_and_explicit_false_does_not() {
    let omitted = compress(CompressRequest {
        payload: EXACT_RUN.to_vec(),
        content_type: ContentType::Auto as i32,
        scope_policy: WireScopePolicy::UserContent as i32,
        options: None,
    })
    .await
    .expect("compress");
    let default_echo = "{\"scope_policy\":\"user_content\",\"min_group_size\":3,\"normalize_ws\":true,\"template_dedup\":true,\"marker_style\":\"auto\",\"reversible\":false}";
    let stats = omitted.stats.expect("stats");
    assert_eq!(stats.options_echo, default_echo);
    assert_eq!(stats.exact_runs, 1);

    let round_tripped = Options::decode(
        Options {
            min_group_size: 5,
            normalize_ws: Some(false),
            template_dedup: Some(false),
            reversible: Some(false),
            marker_style: WireMarkerStyle::Ascii as i32,
        }
        .encode_to_vec()
        .as_slice(),
    )
    .expect("the wire round trip");
    assert_eq!(round_tripped.normalize_ws, Some(false));
    let answer = compress(CompressRequest {
        payload: WS_RUN.to_vec(),
        content_type: ContentType::Auto as i32,
        scope_policy: WireScopePolicy::UserContent as i32,
        options: Some(round_tripped),
    })
    .await
    .expect("compress");
    let stats = answer.stats.expect("stats");
    assert_eq!(stats.ws_runs, 0);
    assert_eq!(
        stats.options_echo,
        "{\"scope_policy\":\"user_content\",\"min_group_size\":5,\"normalize_ws\":false,\"template_dedup\":false,\"marker_style\":\"ascii\",\"reversible\":false}"
    );
    let without = compress(CompressRequest {
        payload: WS_RUN.to_vec(),
        content_type: ContentType::Auto as i32,
        scope_policy: WireScopePolicy::UserContent as i32,
        options: Some(Options::default()),
    })
    .await
    .expect("compress");
    assert_eq!(without.stats.expect("stats").ws_runs, 1);
    assert_ne!(without.payload, answer.payload);
}

#[tokio::test]
async fn a_pinned_content_type_contradiction_is_the_only_invalid_argument() {
    let contradiction = compress(CompressRequest {
        payload: EXACT_RUN.to_vec(),
        content_type: ContentType::Responses as i32,
        scope_policy: WireScopePolicy::UserContent as i32,
        options: Some(Options::default()),
    })
    .await
    .expect_err("responses pinned over a chat payload");
    assert_eq!(contradiction.code(), Code::InvalidArgument);
    assert!(
        contradiction
            .message()
            .contains("content_type_mismatch: pinned responses but the payload sniffs as chat"),
        "{}",
        contradiction.message()
    );

    for (payload, content_type) in [
        (EXACT_RUN, ContentType::Chat),
        (EXACT_RUN, ContentType::Messages),
        (UNKNOWN, ContentType::Text),
        (MALFORMED, ContentType::Text),
        (PLAIN, ContentType::Text),
    ] {
        let answer = compress(CompressRequest {
            payload: payload.to_vec(),
            content_type: content_type as i32,
            scope_policy: WireScopePolicy::UserContent as i32,
            options: Some(Options::default()),
        })
        .await
        .expect("a matching pin is never refused");
        assert_eq!(answer.stats.expect("stats").bytes_in, payload.len() as u64);
    }

    let unknown = compress(CompressRequest {
        payload: UNKNOWN.to_vec(),
        content_type: ContentType::Chat as i32,
        scope_policy: WireScopePolicy::UserContent as i32,
        options: Some(Options::default()),
    })
    .await
    .expect_err("a json pin over an unknown schema");
    assert_eq!(unknown.code(), Code::InvalidArgument);
    assert!(
        unknown.message().contains(
            "content_type_mismatch: pinned chat but the payload sniffs as no known schema"
        ),
        "{}",
        unknown.message()
    );
}

#[tokio::test]
async fn bad_options_are_invalid_argument() {
    for (options, scope_policy, expected) in [
        (
            Options {
                min_group_size: 1,
                ..Options::default()
            },
            WireScopePolicy::UserContent,
            "invalid_options: min_group_size=1 is below the minimum of 2",
        ),
        (
            Options::default(),
            WireScopePolicy::AllMessages,
            "invalid_options: scope_policy=all_messages is reserved",
        ),
        (
            Options::default(),
            WireScopePolicy::ExplicitPaths,
            "invalid_options: scope_policy=explicit_paths is reserved",
        ),
    ] {
        let status = compress(CompressRequest {
            payload: EXACT_RUN.to_vec(),
            content_type: ContentType::Auto as i32,
            scope_policy: scope_policy as i32,
            options: Some(options),
        })
        .await
        .expect_err(expected);
        assert_eq!(status.code(), Code::InvalidArgument, "{expected}");
        assert_eq!(status.message(), expected);
    }
    for (field, status) in [
        ("content_type", {
            let mut request = request(&cases()[0]);
            request.content_type = 9;
            request
        }),
        ("scope_policy", {
            let mut request = request(&cases()[0]);
            request.scope_policy = 9;
            request
        }),
        ("marker_style", {
            let mut request = request(&cases()[0]);
            request.options = Some(Options {
                marker_style: 9,
                ..Options::default()
            });
            request
        }),
    ] {
        let status = compress(status).await.expect_err(field);
        assert_eq!(status.code(), Code::InvalidArgument, "{field}");
        assert!(status.message().contains(field), "{}", status.message());
        assert!(status.message().contains('9'), "{}", status.message());
    }
}

#[tokio::test]
async fn malformed_is_only_refused_in_a_strict_build() {
    let answer = compress(CompressRequest {
        payload: MALFORMED.to_vec(),
        content_type: ContentType::Auto as i32,
        scope_policy: WireScopePolicy::UserContent as i32,
        options: Some(Options::default()),
    })
    .await;
    if api::STRICT_VALIDATE {
        let status = answer.expect_err("strict builds refuse");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(
            status.message().starts_with("malformed: "),
            "{}",
            status.message()
        );
        return;
    }
    let answer = answer.expect("a malformed document passes through");
    assert_eq!(answer.payload, MALFORMED);
    let stats = answer.stats.expect("stats");
    assert!(stats.degraded);
    assert_eq!(stats.noop_reason, "malformed");
    assert_eq!(stats.bytes_in, MALFORMED.len() as u64);
    assert_eq!(stats.bytes_out, MALFORMED.len() as u64);
}

#[tokio::test]
async fn a_degraded_pass_through_is_never_an_error() {
    let mut degraded = vec![(UNKNOWN, "unknown_schema")];
    if !api::STRICT_VALIDATE {
        degraded.push((MALFORMED, "malformed"));
        degraded.push((b"{\"messages\":".as_slice(), "malformed"));
    }
    for (payload, reason) in degraded {
        let answer = compress(CompressRequest {
            payload: payload.to_vec(),
            content_type: ContentType::Auto as i32,
            scope_policy: WireScopePolicy::UserContent as i32,
            options: Some(Options::default()),
        })
        .await
        .expect("a pass-through is a success");
        assert_eq!(answer.payload, payload);
        let stats = answer.stats.expect("stats");
        assert!(stats.degraded, "{reason}");
        assert_eq!(stats.noop_reason, reason);
        assert_eq!(stats.bytes_in, payload.len() as u64);
        assert_eq!(stats.bytes_out, payload.len() as u64);
    }
    for payload in [&b""[..], &b"   "[..], &b"null"[..], &b"{}"[..], &b"[]"[..]] {
        let answer = compress(CompressRequest {
            payload: payload.to_vec(),
            content_type: ContentType::Auto as i32,
            scope_policy: WireScopePolicy::UserContent as i32,
            options: Some(Options::default()),
        })
        .await
        .expect("a degenerate payload is a pass-through, never an error");
        assert_eq!(answer.payload, payload);
    }
}

struct Store;

impl RestoreStore for Store {
    fn restore_verified(&self, restore_id: &str) -> Option<Vec<u8>> {
        restore_id
            .strip_prefix("hit:")
            .map(|rest| rest.as_bytes().to_vec())
    }
}

#[tokio::test]
async fn restore_is_unimplemented_until_a_store_is_wired() {
    let bare = client()
        .restore(RestoreRequest {
            payload: b"whatever".to_vec(),
            restore_id: "hit:7".to_string(),
        })
        .await
        .expect_err("no store in the default service");
    assert_eq!(bare.code(), Code::Unimplemented);
    assert!(
        bare.message().contains(if CCR_ENABLED {
            "not implemented"
        } else {
            "disabled"
        }),
        "{}",
        bare.message()
    );

    let mut client =
        CompressorClient::new(grpc::routes(grpc::Service::with_store(Arc::new(Store))));
    if !CCR_ENABLED {
        let status = client
            .restore(RestoreRequest {
                payload: Vec::new(),
                restore_id: "hit:7".to_string(),
            })
            .await
            .expect_err("disabled");
        assert_eq!(status.code(), Code::Unimplemented);
        return;
    }
    let answer = client
        .restore(RestoreRequest {
            payload: Vec::new(),
            restore_id: "hit:7".to_string(),
        })
        .await
        .expect("a hit");
    assert_eq!(answer.into_inner().original, b"7");
    let miss = client
        .restore(RestoreRequest {
            payload: Vec::new(),
            restore_id: "miss".to_string(),
        })
        .await
        .expect_err("a miss");
    assert_eq!(miss.code(), Code::NotFound);
}

async fn probe(method: &str) -> (i32, String) {
    let mut routes = grpc::routes(grpc::Service::new());
    let request = tonic::codegen::http::Request::builder()
        .method("POST")
        .uri(format!("/{SERVICE}/{method}"))
        .header("content-type", "application/grpc")
        .body(tonic::body::Body::empty())
        .expect("request");
    let response = routes.call(request).await.expect("routed");
    let status = response
        .headers()
        .get("grpc-status")
        .expect("a grpc status")
        .to_str()
        .expect("ascii")
        .parse()
        .expect("a number");
    let message = response
        .headers()
        .get("grpc-message")
        .map(|value| percent_decode(value.to_str().expect("ascii")))
        .unwrap_or_default();
    (status, message)
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' && at + 2 < bytes.len() {
            let high = (bytes[at + 1] as char).to_digit(16);
            let low = (bytes[at + 2] as char).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                out.push((high * 16 + low) as u8);
                at += 3;
                continue;
            }
        }
        out.push(bytes[at]);
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn the_service_exposes_two_unary_methods_and_no_streaming_ones() {
    for method in ["Compress", "Restore"] {
        let (status, _) = probe(method).await;
        assert_ne!(
            status,
            Code::Unimplemented as i32,
            "{method} must be routed to the service"
        );
    }
    for method in [
        "CompressStream",
        "CompressBidiStream",
        "CompressServerStream",
        "CompressChunked",
        "StreamCompress",
        "Subscribe",
        "Watch",
    ] {
        let (status, message) = probe(method).await;
        assert_eq!(
            status,
            Code::Unimplemented as i32,
            "{method} is not a method of {SERVICE}"
        );
        assert_eq!(message, "", "{method} is not routed at all");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_response_is_a_real_grpc_message_over_a_socket() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(grpc::server(grpc::Service::new()))
            .serve_with_incoming(tonic::transport::server::TcpIncoming::from(listener))
            .await;
    });
    let mut client = CompressorClient::connect(format!("http://{address}"))
        .await
        .expect("connect");
    let answer = client
        .compress(request(&cases()[1]))
        .await
        .expect("compress");
    let answer = answer.into_inner();
    let (expected, stats) = core(TEMPLATE_RUN, core_request(&cases()[1]));
    assert_eq!(answer.payload, expected);
    let served = answer.stats.expect("stats");
    assert_eq!(served.bytes_in, stats.bytes_in);
    assert_eq!(served.template_groups, stats.template_groups);
    assert_eq!(
        served.options_echo,
        "{\"scope_policy\":\"user_content\",\"min_group_size\":3,\"normalize_ws\":true,\"template_dedup\":true,\"marker_style\":\"auto\",\"reversible\":false}"
    );
}

fn deterministic(answer: &CompressResponse) -> Vec<u8> {
    let mut answer = answer.clone();
    let stats = answer.stats.as_mut().expect("stats");
    stats.elapsed_detect_ns = 0;
    stats.elapsed_compact_ns = 0;
    stats.elapsed_splice_ns = 0;
    answer.encode_to_vec()
}

#[tokio::test]
async fn repeated_identical_requests_answer_byte_identically() {
    let first = compress(request(&cases()[1])).await.expect("compress");
    let reference = deterministic(&first);
    for _ in 0..7 {
        let again = compress(request(&cases()[1])).await.expect("compress");
        assert_eq!(
            deterministic(&again),
            reference,
            "the answer must not carry a thread, a clock or a run-dependent byte"
        );
    }
    let http = http_bytes("/v1/compress", TEMPLATE_RUN).await;
    assert_eq!(http.as_ref(), first.payload.as_slice());
    assert!(!reference.is_empty());
}

#[tokio::test]
async fn reversible_true_is_refused_by_both_transports_and_false_resolves() {
    let refused = case(
        "reversible_true",
        EXACT_RUN,
        "?reversible=true",
        ContentType::Auto,
        WireScopePolicy::UserContent,
        Options {
            reversible: Some(true),
            ..Options::default()
        },
    );
    let status = compress(request(&refused)).await.expect_err("refused");
    assert_eq!(status.code(), Code::InvalidArgument);
    assert!(
        status.message().contains("reversible"),
        "{} must name the option",
        status.message()
    );
    let (http_status, body) =
        http_status_and_bytes("/v1/compress?reversible=true", EXACT_RUN).await;
    assert_eq!(http_status, 400, "the transports must agree");
    let http: Value = serde_json::from_slice(&body).expect("error json");
    assert_eq!(http["error"]["code"], "invalid_options");

    let off = case(
        "reversible_false",
        EXACT_RUN,
        "?reversible=false",
        ContentType::Auto,
        WireScopePolicy::UserContent,
        Options {
            reversible: Some(false),
            ..Options::default()
        },
    );
    let answer = compress(request(&off)).await.expect("false resolves");
    assert_eq!(
        answer.payload,
        http_bytes("/v1/compress?reversible=false", EXACT_RUN).await
    );
    let stats = answer.stats.expect("stats");
    assert!(
        stats.options_echo.ends_with("\"reversible\":false}"),
        "{}",
        stats.options_echo
    );
    assert!(
        stats.restore_ids.is_empty(),
        "no store, so no ids next to the echoed false"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_over_the_tonic_default_but_under_the_limit_is_accepted() {
    let filler = "a".repeat(5 * 1024 * 1024);
    let payload = format!(r#"{{"messages":[{{"role":"user","content":"{filler}"}}]}}"#);
    let answer = compress(CompressRequest {
        payload: payload.as_bytes().to_vec(),
        content_type: ContentType::Auto as i32,
        scope_policy: WireScopePolicy::UserContent as i32,
        options: Some(Options::default()),
    })
    .await
    .expect("five mebibytes is over tonic's four megabyte default");
    assert_eq!(answer.payload, payload.as_bytes());
    assert_eq!(answer.stats.expect("stats").bytes_in, payload.len() as u64);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_over_sixty_four_mebibytes_is_out_of_range() {
    let answer = compress(CompressRequest {
        payload: vec![b'x'; REQUEST_BODY_LIMIT + 1],
        content_type: ContentType::Auto as i32,
        scope_policy: WireScopePolicy::UserContent as i32,
        options: Some(Options::default()),
    })
    .await
    .expect_err("over the section seven limit");
    assert_eq!(answer.code(), Code::OutOfRange, "tonic's length guard");
    assert!(
        answer
            .message()
            .contains(&format!("the limit is: {REQUEST_BODY_LIMIT} bytes")),
        "{}",
        answer.message()
    );
}
