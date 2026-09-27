pub mod grpc;
mod headers;
mod options;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, RawQuery, State as AxumState};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use quantification_core::api::{
    self, ALGO_VERSION, ApiError, Compressor, Request, ScopePolicy, Stats,
};
use quantification_core::ccr;
use quantification_core::config::REQUEST_BODY_LIMIT;
use quantification_core::locator::{self, SpanClass};
use serde_json::json;

pub const CCR_ENABLED: bool = cfg!(feature = "ccr");
pub const SPAN_PREVIEW_LIMIT: usize = 64;

const JSON: &str = "application/json";
const PLAIN: &str = "text/plain; version=0.0.4; charset=utf-8";
const OCTET: &str = "application/octet-stream";

const COMPRESS: u8 = 0;
const DETECT: u8 = 1;
const RESTORE: u8 = 2;

const CCR_MISSING: &str = "the reversible store (DESIGN section 9) is not implemented here because no store is wired; reversible=true stores no span, so no restore_id is returned";
const CCR_DISABLED: &str = "the reversible store (DESIGN section 9) is disabled in this build; reversible=true stores no span, so no restore_id is returned";

pub trait RestoreStore: Send + Sync {
    fn store_committed(
        &self,
        _original: &[u8],
        _marker: &[u8],
        _checksum: [u8; 4],
    ) -> Option<ccr::RestoreId> {
        None
    }

    fn restore_verified(&self, payload: &[u8], restore_id: &str) -> Option<Vec<u8>>;
}

impl RestoreStore for ccr::Shared {
    fn store_committed(
        &self,
        original: &[u8],
        marker: &[u8],
        checksum: [u8; 4],
    ) -> Option<ccr::RestoreId> {
        self.put(original, marker, checksum)
    }

    fn restore_verified(&self, payload: &[u8], restore_id: &str) -> Option<Vec<u8>> {
        self.restore(Some(payload), restore_id)
    }
}

pub fn shared_store() -> Option<Arc<dyn RestoreStore>> {
    CCR_ENABLED.then(|| Arc::new(ccr::Shared::default()) as Arc<dyn RestoreStore>)
}

pub(crate) struct SinkHandle(pub(crate) Arc<dyn RestoreStore>);

impl ccr::Sink for SinkHandle {
    fn store(
        &mut self,
        original: &[u8],
        marker: &[u8],
        checksum: [u8; 4],
    ) -> Option<ccr::RestoreId> {
        self.0.store_committed(original, marker, checksum)
    }
}

#[derive(Clone)]
pub struct State {
    metrics: Arc<Mutex<Metrics>>,
    store: Option<Arc<dyn RestoreStore>>,
}

pub fn app(state: State) -> Router {
    Router::new()
        .route("/v1/compress", post(compress))
        .route("/v1/detect", post(detect))
        .route("/v1/restore", post(restore))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .layer(DefaultBodyLimit::max(REQUEST_BODY_LIMIT))
        .with_state(state)
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(Mutex::new(Metrics::default())),
            store: shared_store(),
        }
    }

    pub fn with_store(store: Arc<dyn RestoreStore>) -> Self {
        Self {
            metrics: Arc::new(Mutex::new(Metrics::default())),
            store: Some(store),
        }
    }

    pub fn without_store() -> Self {
        Self {
            metrics: Arc::new(Mutex::new(Metrics::default())),
            store: None,
        }
    }

    pub fn store(&self) -> Option<Arc<dyn RestoreStore>> {
        self.store.clone()
    }

    fn record(&self, route: u8, status: StatusCode, in_len: u64, out_len: u64, degraded: bool) {
        let mut metrics = lock(&self.metrics);
        *metrics
            .requests
            .entry((route, status.as_u16()))
            .or_default() += 1;
        metrics.bytes_in += in_len;
        metrics.bytes_out += out_len;
        metrics.degraded += u64::from(degraded);
    }

    fn fault(&self, route: u8, fault: Fault) -> Response {
        let body = json!({"error": {"code": fault.code, "message": fault.message}}).to_string();
        let out_len = body.len() as u64;
        let response = reply(fault.status, JSON, Bytes::from(body));
        self.record(route, fault.status, 0, out_len, false);
        response
    }
}

struct Outcome {
    in_len: u64,
    degraded: bool,
    content_type: String,
    body: Bytes,
    stats: Option<Stats>,
}

struct Fault {
    status: StatusCode,
    code: &'static str,
    message: String,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn bad_request(message: String) -> Fault {
    Fault {
        status: StatusCode::BAD_REQUEST,
        code: "invalid_argument",
        message,
    }
}

fn reply(status: StatusCode, content_type: &str, body: Bytes) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).expect("content type is ascii"),
    );
    response
}

async fn compress(
    AxumState(state): AxumState<State>,
    RawQuery(raw): RawQuery,
    request_headers: HeaderMap,
    body: Bytes,
) -> Response {
    let query = options::Query::parse(raw.as_deref());
    match compress_inner(&query, &request_headers, body, state.store()).await {
        Ok(outcome) => {
            let out_len = outcome.body.len() as u64;
            let mut response = reply(StatusCode::OK, &outcome.content_type, outcome.body.clone());
            if let Some(stats) = &outcome.stats {
                headers::apply(response.headers_mut(), stats);
            }
            state.record(
                COMPRESS,
                StatusCode::OK,
                outcome.in_len,
                out_len,
                outcome.degraded,
            );
            response
        }
        Err(fault) => state.fault(COMPRESS, fault),
    }
}

async fn compress_inner(
    query: &options::Query,
    request_headers: &HeaderMap,
    body: Bytes,
    store: Option<Arc<dyn RestoreStore>>,
) -> Result<Outcome, Fault> {
    match query.get("envelope") {
        None => {
            let request = options::request(query).map_err(bad_request)?;
            let mut outcome = compress_once(body, request, store).await?;
            outcome.content_type = request_headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or(JSON)
                .to_string();
            Ok(outcome)
        }
        Some("json") => {
            options::only_envelope(query).map_err(bad_request)?;
            let envelope: options::Envelope = serde_json::from_slice(&body).map_err(|error| {
                bad_request(format!(
                    "envelope is not a valid {{payload, options}} document: {error}"
                ))
            })?;
            let request = envelope.request().map_err(bad_request)?;
            let mut outcome = compress_once(Bytes::from(envelope.payload), request, store).await?;
            let stats = outcome.stats.take().expect("compress_once sets stats");
            outcome.body = Bytes::from(
                json!({
                    "payload": String::from_utf8_lossy(&outcome.body),
                    "stats": stats_json(&stats),
                })
                .to_string(),
            );
            Ok(outcome)
        }
        Some(other) => Err(bad_request(format!(
            "envelope={other} is not accepted; expected json"
        ))),
    }
}

async fn compress_once(
    payload: Bytes,
    request: Request,
    store: Option<Arc<dyn RestoreStore>>,
) -> Result<Outcome, Fault> {
    let in_len = payload.len() as u64;
    let compressed = tokio::task::spawn_blocking(move || {
        let mut compressor = Compressor::new();
        if let Some(store) = store {
            compressor = compressor.with_sink(SinkHandle(store));
        }
        let mut out = Vec::new();
        api::reserve(&mut out, payload.len());
        let stats = compressor
            .compress(&payload, &request, &mut out)
            .map_err(fault_of)?;
        Ok::<_, Fault>((Bytes::from(out), stats))
    })
    .await
    .map_err(|error| Fault {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        code: "internal_error",
        message: format!("the compression task did not finish: {error}"),
    })??;
    let (body, stats) = compressed;
    Ok(Outcome {
        in_len,
        degraded: stats.degraded,
        content_type: JSON.to_string(),
        body,
        stats: Some(stats),
    })
}

fn fault_of(error: ApiError) -> Fault {
    let (status, code, message) = match error {
        ApiError::Options(inner) => (
            StatusCode::BAD_REQUEST,
            "invalid_options",
            options::resolve_message(inner),
        ),
        ApiError::Malformed => (
            StatusCode::BAD_REQUEST,
            "malformed",
            "the payload is not valid json and this build validates strictly".to_string(),
        ),
        ApiError::ContentTypeMismatch { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "content_type_mismatch",
            error.to_string(),
        ),
    };
    Fault {
        status,
        code,
        message,
    }
}

fn stats_json(stats: &Stats) -> serde_json::Value {
    json!({
        "bytes_in": stats.bytes_in,
        "bytes_out": stats.bytes_out,
        "approx_tokens_in": stats.approx_tokens_in,
        "approx_tokens_out": stats.approx_tokens_out,
        "groups_collapsed": stats.groups_collapsed,
        "exact_runs": stats.exact_runs,
        "ws_runs": stats.ws_runs,
        "block_repeats": stats.block_repeats,
        "template_groups": stats.template_groups,
        "degraded": stats.degraded,
        "noop_reason": stats.noop_reason.map(|reason| reason.as_str()),
        "elapsed_detect_ns": stats.elapsed_detect_ns,
        "elapsed_compact_ns": stats.elapsed_compact_ns,
        "elapsed_splice_ns": stats.elapsed_splice_ns,
        "algo_version": stats.algo_version,
        "templated_blocks": stats.templated_blocks,
        "options_echo": stats.options_echo,
        "record_splits": stats.record_splits,
        "restore_ids": stats.restore_ids,
    })
}

async fn detect(
    AxumState(state): AxumState<State>,
    RawQuery(raw): RawQuery,
    body: Bytes,
) -> Response {
    let query = options::Query::parse(raw.as_deref());
    let outcome = options::scope(&query)
        .map_err(bad_request)
        .and_then(|policy| detect_payload(&body, policy));
    match outcome {
        Ok(outcome) => {
            let out_len = outcome.body.len() as u64;
            let response = reply(StatusCode::OK, &outcome.content_type, outcome.body);
            state.record(
                DETECT,
                StatusCode::OK,
                outcome.in_len,
                out_len,
                outcome.degraded,
            );
            response
        }
        Err(fault) => state.fault(DETECT, fault),
    }
}

fn detect_payload(payload: &[u8], policy: ScopePolicy) -> Result<Outcome, Fault> {
    let located = locator::locate(payload, policy);
    let spans: Vec<serde_json::Value> = located
        .spans
        .iter()
        .take(SPAN_PREVIEW_LIMIT)
        .map(|span| {
            json!({
                "start": span.start,
                "end": span.end,
                "class": match span.class {
                    SpanClass::User => "user",
                    SpanClass::Tool => "tool",
                },
            })
        })
        .collect();
    let body = json!({
        "schema": located.schema.map(|schema| schema.as_str()),
        "degraded": located.degraded(),
        "noop_reason": located.noop_reason.map(|reason| reason.as_str()),
        "scope_policy": policy.as_str(),
        "span_count": located.spans.len(),
        "spans_truncated": located.spans.len() > SPAN_PREVIEW_LIMIT,
        "spans": spans,
    })
    .to_string();
    Ok(Outcome {
        in_len: payload.len() as u64,
        degraded: located.degraded(),
        content_type: JSON.to_string(),
        body: Bytes::from(body),
        stats: None,
    })
}

async fn restore(
    AxumState(state): AxumState<State>,
    RawQuery(raw): RawQuery,
    body: Bytes,
) -> Response {
    if !CCR_ENABLED {
        return state.fault(RESTORE, unimplemented(CCR_DISABLED));
    }
    let Some(store) = state.store() else {
        return state.fault(RESTORE, unimplemented(CCR_MISSING));
    };
    let query = options::Query::parse(raw.as_deref());
    let (payload, restore_id) = match options::restore(&query, &body) {
        Ok(asked) => asked,
        Err(message) => return state.fault(RESTORE, bad_request(message)),
    };
    let in_len = payload.len() as u64;
    let Some(original) = store.restore_verified(&payload, &restore_id) else {
        return state.fault(
            RESTORE,
            Fault {
                status: StatusCode::NOT_FOUND,
                code: "not_found",
                message: format!("no stored span for restore_id {restore_id}"),
            },
        );
    };
    let out_len = original.len() as u64;
    let response = reply(StatusCode::OK, OCTET, Bytes::from(original));
    state.record(RESTORE, StatusCode::OK, in_len, out_len, false);
    response
}

fn unimplemented(message: &str) -> Fault {
    Fault {
        status: StatusCode::NOT_IMPLEMENTED,
        code: "not_implemented",
        message: message.to_string(),
    }
}

async fn healthz() -> Response {
    reply(
        StatusCode::OK,
        JSON,
        Bytes::from_static(b"{\"status\":\"ok\"}"),
    )
}

async fn readyz() -> Response {
    reply(
        StatusCode::OK,
        JSON,
        Bytes::from_static(b"{\"status\":\"ready\"}"),
    )
}

async fn metrics(AxumState(state): AxumState<State>) -> Response {
    let rendered = lock(&state.metrics).render();
    reply(StatusCode::OK, PLAIN, Bytes::from(rendered))
}

#[derive(Default)]
struct Metrics {
    requests: BTreeMap<(u8, u16), u64>,
    bytes_in: u64,
    bytes_out: u64,
    degraded: u64,
}

impl Metrics {
    fn render(&self) -> String {
        let mut out = String::from(
            "# HELP quantification_http_requests_total Requests served, by route and status.\n\
             # TYPE quantification_http_requests_total counter\n",
        );
        for ((route, status), count) in &self.requests {
            out.push_str(&format!(
                "quantification_http_requests_total{{route=\"{}\",status=\"{status}\"}} {count}\n",
                route_name(*route)
            ));
        }
        out.push_str(
            "# HELP quantification_payload_bytes_total Payload bytes handled, by direction.\n\
             # TYPE quantification_payload_bytes_total counter\n",
        );
        out.push_str(&format!(
            "quantification_payload_bytes_total{{direction=\"in\"}} {}\n\
             quantification_payload_bytes_total{{direction=\"out\"}} {}\n",
            self.bytes_in, self.bytes_out
        ));
        out.push_str(
            "# HELP quantification_pass_through_total Responses that passed a payload through untouched.\n\
             # TYPE quantification_pass_through_total counter\n",
        );
        out.push_str(&format!(
            "quantification_pass_through_total {}\n",
            self.degraded
        ));
        out.push_str(
            "# HELP quantification_build_info Algorithm version and build flags.\n\
             # TYPE quantification_build_info gauge\n",
        );
        out.push_str(&format!(
            "quantification_build_info{{algo_version=\"{ALGO_VERSION}\",ccr=\"{CCR_ENABLED}\"}} 1\n"
        ));
        out
    }
}

fn route_name(route: u8) -> &'static str {
    match route {
        COMPRESS => "/v1/compress",
        DETECT => "/v1/detect",
        RESTORE => "/v1/restore",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAT: &[u8] =
        br#"{"messages":[{"role":"user","content":"ERROR timeout\nERROR timeout\nERROR timeout\nERROR done"}]}"#;

    #[test]
    fn metrics_render_in_prometheus_text_format() {
        let state = State::new();
        state.record(COMPRESS, StatusCode::OK, 120, 60, false);
        state.record(COMPRESS, StatusCode::OK, 30, 30, true);
        state.record(COMPRESS, StatusCode::BAD_REQUEST, 0, 40, false);
        let rendered = lock(&state.metrics).render();
        assert!(rendered.contains(
            "quantification_http_requests_total{route=\"/v1/compress\",status=\"200\"} 2\n"
        ));
        assert!(rendered.contains(
            "quantification_http_requests_total{route=\"/v1/compress\",status=\"400\"} 1\n"
        ));
        assert!(rendered.contains("quantification_payload_bytes_total{direction=\"in\"} 150\n"));
        assert!(rendered.contains("quantification_pass_through_total 1\n"));
        assert!(rendered.contains(&format!(
            "quantification_build_info{{algo_version=\"{ALGO_VERSION}\",ccr=\"{CCR_ENABLED}\"}} 1\n"
        )));
        assert_eq!(
            rendered
                .lines()
                .filter(|line| line.starts_with('#'))
                .count(),
            8
        );
    }

    #[tokio::test]
    async fn a_poisoned_metrics_lock_still_serves() {
        let state = State::new();
        let metrics = state.metrics.clone();
        let poisoner = tokio::task::spawn_blocking(move || {
            let _held = metrics.lock().expect("unpoisoned");
            panic!("a poisoned lock must not take the server down");
        });
        assert!(poisoner.await.expect_err("panicked").is_panic());
        let response = compress(
            AxumState(state),
            RawQuery(None),
            HeaderMap::new(),
            Bytes::from_static(CHAT),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
