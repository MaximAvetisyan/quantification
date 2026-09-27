use std::sync::Arc;

use quantification_core::api::{self, ApiError, Compressor as Core, ContentType, Request, Stats};
use quantification_core::config::REQUEST_BODY_LIMIT;
use quantification_proto::compressor::v1::compressor_server::{
    Compressor as Rpc, CompressorServer,
};
use quantification_proto::compressor::v1::{
    CompressRequest, CompressResponse, ContentType as WireContentType,
    MarkerStyle as WireMarkerStyle, RestoreRequest, RestoreResponse,
    ScopePolicy as WireScopePolicy, Stats as GrpcStats,
};
use quantification_proto::convert::to_raw_options;
use tonic::service::Routes;
use tonic::{Request as RpcRequest, Response, Status};

use crate::options;
use crate::{CCR_DISABLED, CCR_ENABLED, CCR_MISSING, SinkHandle, shared_store};

pub use crate::RestoreStore;

#[derive(Clone)]
pub struct Service {
    store: Option<Arc<dyn RestoreStore>>,
}

impl Default for Service {
    fn default() -> Self {
        Self {
            store: shared_store(),
        }
    }
}

impl Service {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_store(store: Arc<dyn RestoreStore>) -> Self {
        Self { store: Some(store) }
    }

    fn restored(&self, payload: &[u8], restore_id: &str) -> Result<Vec<u8>, Status> {
        if !CCR_ENABLED {
            return Err(Status::unimplemented(CCR_DISABLED));
        }
        let store = self
            .store
            .as_deref()
            .ok_or_else(|| Status::unimplemented(CCR_MISSING))?;
        store
            .restore_verified(payload, restore_id)
            .ok_or_else(|| Status::not_found(format!("no stored span for restore_id {restore_id}")))
    }
}

pub fn server(service: Service) -> CompressorServer<Service> {
    CompressorServer::new(service).max_decoding_message_size(REQUEST_BODY_LIMIT)
}

pub fn routes(service: Service) -> Routes {
    let mut builder = Routes::builder();
    builder.add_service(server(service));
    builder.routes()
}

#[tonic::async_trait]
impl Rpc for Service {
    async fn compress(
        &self,
        request: RpcRequest<CompressRequest>,
    ) -> Result<Response<CompressResponse>, Status> {
        let core = core_request(request.get_ref())?;
        let payload = request.into_inner().payload;
        let store = self.store.clone();
        let compressed = tokio::task::spawn_blocking(move || {
            let mut compressor = Core::new();
            if let Some(store) = store {
                compressor = compressor.with_sink(SinkHandle(store));
            }
            let mut out = Vec::new();
            api::reserve(&mut out, payload.len());
            let stats = compressor
                .compress(&payload, &core, &mut out)
                .map_err(status_of)?;
            Ok::<_, Status>((out, stats))
        })
        .await
        .map_err(|error| {
            Status::internal(format!("the compression task did not finish: {error}"))
        })??;
        let (payload, stats) = compressed;
        Ok(Response::new(CompressResponse {
            payload,
            stats: Some(stats_message(&stats)),
        }))
    }

    async fn restore(
        &self,
        request: RpcRequest<RestoreRequest>,
    ) -> Result<Response<RestoreResponse>, Status> {
        let asked = request.get_ref();
        let original = self.restored(asked.payload.as_slice(), asked.restore_id.as_str())?;
        Ok(Response::new(RestoreResponse { original }))
    }
}

fn core_request(message: &CompressRequest) -> Result<Request, Status> {
    WireScopePolicy::try_from(message.scope_policy)
        .map_err(|_| unknown_enum("scope_policy", message.scope_policy))?;
    let options = message.options.unwrap_or_default();
    WireMarkerStyle::try_from(options.marker_style)
        .map_err(|_| unknown_enum("marker_style", options.marker_style))?;
    Ok(Request {
        content_type: pinned(message.content_type)?,
        options: to_raw_options(message),
    })
}

fn pinned(value: i32) -> Result<Option<ContentType>, Status> {
    match WireContentType::try_from(value).map_err(|_| unknown_enum("content_type", value))? {
        WireContentType::Auto => Ok(None),
        WireContentType::Chat => Ok(Some(ContentType::Chat)),
        WireContentType::Responses => Ok(Some(ContentType::Responses)),
        WireContentType::Messages => Ok(Some(ContentType::Messages)),
        WireContentType::Text => Ok(Some(ContentType::Text)),
    }
}

fn unknown_enum(field: &str, value: i32) -> Status {
    Status::invalid_argument(format!(
        "invalid_argument: {field}={value} is not a value of its compressor.v1 enum"
    ))
}

fn status_of(error: ApiError) -> Status {
    let code = error.as_str();
    match error {
        ApiError::Options(inner) => {
            Status::invalid_argument(format!("{code}: {}", options::resolve_message(inner)))
        }
        ApiError::Malformed => Status::invalid_argument(format!(
            "{code}: the payload is not valid json and this build validates strictly"
        )),
        ApiError::ContentTypeMismatch { .. } => Status::invalid_argument(error.to_string()),
    }
}

fn stats_message(stats: &Stats) -> GrpcStats {
    GrpcStats {
        bytes_in: stats.bytes_in,
        bytes_out: stats.bytes_out,
        approx_tokens_in: stats.approx_tokens_in,
        approx_tokens_out: stats.approx_tokens_out,
        groups_collapsed: stats.groups_collapsed,
        exact_runs: stats.exact_runs,
        ws_runs: stats.ws_runs,
        block_repeats: stats.block_repeats,
        template_groups: stats.template_groups,
        degraded: stats.degraded,
        noop_reason: stats
            .noop_reason
            .map_or_else(String::new, |reason| reason.as_str().to_string()),
        elapsed_detect_ns: stats.elapsed_detect_ns,
        elapsed_compact_ns: stats.elapsed_compact_ns,
        elapsed_splice_ns: stats.elapsed_splice_ns,
        algo_version: stats.algo_version.to_string(),
        templated_blocks: stats.templated_blocks,
        options_echo: stats.options_echo.clone(),
        record_splits: stats.record_splits,
        restore_ids: stats.restore_ids.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use quantification_core::api::{MarkerStyle, NoopReason, ResolveError, ScopePolicy};
    use quantification_core::config::resolve;
    use quantification_proto::compressor::v1::{Options, ScopePolicy as WireScopePolicy};
    use tonic::Code;

    use super::*;

    fn message(options: Options) -> CompressRequest {
        CompressRequest {
            payload: b"[]".to_vec(),
            content_type: WireContentType::Auto as i32,
            scope_policy: WireScopePolicy::UserContent as i32,
            options: Some(options),
        }
    }

    #[test]
    fn every_content_type_maps_onto_the_core_schema() {
        for (wire, expected) in [
            (WireContentType::Auto, None),
            (WireContentType::Chat, Some(ContentType::Chat)),
            (WireContentType::Responses, Some(ContentType::Responses)),
            (WireContentType::Messages, Some(ContentType::Messages)),
            (WireContentType::Text, Some(ContentType::Text)),
        ] {
            let mut request = message(Options::default());
            request.content_type = wire as i32;
            assert_eq!(core_request(&request).unwrap().content_type, expected);
        }
    }

    #[test]
    fn an_unknown_enum_value_is_an_invalid_argument() {
        for field in ["content_type", "scope_policy", "marker_style"] {
            let mut request = message(Options::default());
            match field {
                "content_type" => request.content_type = 7,
                "scope_policy" => request.scope_policy = 7,
                _ => request.options.as_mut().expect("options").marker_style = 7,
            }
            let status = core_request(&request).expect_err(field);
            assert_eq!(status.code(), Code::InvalidArgument, "{field}");
            assert!(status.message().contains(field), "{}", status.message());
            assert!(status.message().contains('7'), "{}", status.message());
        }
    }

    #[test]
    fn the_options_use_the_proto_presence_semantics() {
        let omitted = core_request(&message(Options::default())).unwrap();
        assert_eq!(omitted.options.normalize_ws, None);
        assert_eq!(omitted.options.template_dedup, None);
        assert_eq!(omitted.options.reversible, None);
        assert_eq!(omitted.options.min_group_size, Some(0));
        let explicit = core_request(&message(Options {
            normalize_ws: Some(false),
            template_dedup: Some(false),
            reversible: Some(false),
            min_group_size: 5,
            marker_style: WireMarkerStyle::Ascii as i32,
        }))
        .unwrap();
        assert_eq!(explicit.options.normalize_ws, Some(false));
        assert_eq!(explicit.options.template_dedup, Some(false));
        assert_eq!(explicit.options.reversible, Some(false));
        assert_eq!(explicit.options.min_group_size, Some(5));
        assert_eq!(explicit.options.marker_style, Some(MarkerStyle::Ascii));
    }

    #[test]
    fn the_status_mapping_is_exact() {
        let cases = [
            (
                ApiError::Options(ResolveError::MinGroupSizeBelowTwo(1)),
                "invalid_options: min_group_size=1 is below the minimum of 2",
            ),
            (
                ApiError::Options(ResolveError::UnsupportedScopePolicy(
                    ScopePolicy::AllMessages,
                )),
                "invalid_options: scope_policy=all_messages is reserved",
            ),
            (
                ApiError::Malformed,
                "malformed: the payload is not valid json and this build validates strictly",
            ),
            (
                ApiError::ContentTypeMismatch {
                    pinned: ContentType::Responses,
                    sniffed: Some(ContentType::Chat),
                },
                "content_type_mismatch: pinned responses but the payload sniffs as chat",
            ),
            (
                ApiError::ContentTypeMismatch {
                    pinned: ContentType::Chat,
                    sniffed: None,
                },
                "content_type_mismatch: pinned chat but the payload sniffs as no known schema",
            ),
        ];
        for (error, expected) in cases {
            let status = status_of(error);
            assert_eq!(status.code(), Code::InvalidArgument);
            assert_eq!(status.message(), expected);
        }
    }

    #[test]
    fn every_core_stat_reaches_the_message() {
        let payload = br#"{"messages":[{"role":"user","content":"ERROR timeout\nERROR timeout\nERROR timeout\nERROR done"}]}"#;
        let mut compressor = Core::new();
        let mut out = Vec::new();
        let stats = compressor
            .compress(payload, &Request::default(), &mut out)
            .expect("the core never fails this payload");
        let message = stats_message(&stats);
        assert_eq!(
            message,
            GrpcStats {
                bytes_in: payload.len() as u64,
                bytes_out: out.len() as u64,
                approx_tokens_in: payload.len() as u64 / 4,
                approx_tokens_out: out.len() as u64 / 4,
                groups_collapsed: 1,
                exact_runs: 1,
                ws_runs: 0,
                block_repeats: 0,
                template_groups: 0,
                degraded: false,
                noop_reason: String::new(),
                elapsed_detect_ns: stats.elapsed_detect_ns,
                elapsed_compact_ns: stats.elapsed_compact_ns,
                elapsed_splice_ns: stats.elapsed_splice_ns,
                algo_version: "0.1.0".to_string(),
                templated_blocks: 0,
                options_echo: resolve(&Default::default())
                    .expect("defaults resolve")
                    .options_echo(),
                record_splits: 0,
                restore_ids: Vec::new(),
            }
        );
    }

    #[test]
    fn a_degraded_pass_through_carries_its_reason() {
        let message = stats_message(&Stats {
            degraded: true,
            noop_reason: Some(NoopReason::UnknownSchema),
            ..Stats::default()
        });
        assert_eq!(message.noop_reason, "unknown_schema");
        assert!(message.degraded);
    }

    struct Store {
        original: Vec<u8>,
        asked: Arc<Mutex<Vec<String>>>,
    }

    impl RestoreStore for Store {
        fn restore_verified(&self, payload: &[u8], restore_id: &str) -> Option<Vec<u8>> {
            self.asked
                .lock()
                .expect("unpoisoned")
                .push(restore_id.to_string());
            (restore_id == "hit" && payload != b"wrong").then(|| self.original.clone())
        }
    }

    #[test]
    fn restore_is_gated_on_the_ccr_feature() {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let store = Store {
            original: vec![7, 7],
            asked: asked.clone(),
        };
        let wired = Service::with_store(Arc::new(store));
        if !CCR_ENABLED {
            let status = Service::new()
                .restored(b"", "hit")
                .expect_err("disabled in this build");
            assert_eq!(status.code(), Code::Unimplemented);
            assert_eq!(status.message(), CCR_DISABLED);
            let status = wired.restored(b"", "hit").expect_err("disabled");
            assert_eq!(status.code(), Code::Unimplemented);
            assert_eq!(status.message(), CCR_DISABLED);
            assert!(asked.lock().expect("unpoisoned").is_empty());
            return;
        }
        assert_eq!(wired.restored(b"", "hit").expect("hit"), vec![7, 7]);
        assert_eq!(
            wired.restored(b"", "miss").expect_err("a miss").code(),
            Code::NotFound
        );
        assert_eq!(
            wired
                .restored(b"wrong", "hit")
                .expect_err("a pre-check miss")
                .code(),
            Code::NotFound
        );
        assert_eq!(*asked.lock().expect("unpoisoned"), ["hit", "miss", "hit"]);
        let bare = Service::new();
        assert_eq!(
            bare.store.is_some(),
            CCR_ENABLED,
            "the default service wires the reversible store when the feature is on"
        );
        let unwired = Service { store: None };
        let status = unwired.restored(b"", "hit").expect_err("no store");
        assert_eq!(status.code(), Code::Unimplemented);
        assert_eq!(status.message(), CCR_MISSING);
    }

    #[test]
    fn the_service_is_the_documented_compressor_service() {
        use tonic::server::NamedService;
        assert_eq!(
            <CompressorServer<Service> as NamedService>::NAME,
            "compressor.v1.Compressor"
        );
    }

    #[test]
    fn the_proto_declares_no_streaming_rpc() {
        let text =
            std::str::from_utf8(quantification_proto::COMPRESSOR_PROTO).expect("a utf8 proto");
        assert!(
            !text.contains("stream"),
            "section 5.6 keeps streaming rpcs out"
        );
        let rpcs: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("rpc "))
            .collect();
        assert_eq!(
            rpcs,
            vec![
                "rpc Compress(CompressRequest) returns (CompressResponse);",
                "rpc Restore(RestoreRequest) returns (RestoreResponse);",
            ]
        );
    }
}
