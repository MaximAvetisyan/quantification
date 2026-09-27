use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::http::{Request, StatusCode, header};
use quantification_core::ccr;
use quantification_proto::compressor::v1::compressor_client::CompressorClient;
use quantification_proto::compressor::v1::{
    CompressRequest, ContentType, Options, RestoreRequest, ScopePolicy as WireScopePolicy,
};
use quantification_server::grpc::{self, RestoreStore};
use quantification_server::{CCR_ENABLED, RestoreStore as RootStore, State, app, shared_store};
use serde_json::Value;
use tonic::Code;
use tower::ServiceExt;

const RUN: &str = "ERROR timeout while connecting to the primary database shard";
const WARN: &str = "WARN retrying the secondary replica after a slow handshake";

fn group(line: &str, count: usize) -> String {
    std::iter::repeat_n(line, count)
        .collect::<Vec<_>>()
        .join(r"\n")
}

fn payload() -> Vec<u8> {
    format!(
        r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"{}\n{}"}}]}}"#,
        group(RUN, 4),
        group(WARN, 5)
    )
    .into_bytes()
}

fn compress_request() -> CompressRequest {
    CompressRequest {
        payload: payload(),
        content_type: ContentType::Auto as i32,
        scope_policy: WireScopePolicy::UserContent as i32,
        options: Some(Options {
            reversible: Some(true),
            ..Options::default()
        }),
    }
}

fn router(store: Option<Arc<dyn RootStore>>) -> Router {
    match store {
        Some(store) => app(State::with_store(store)),
        None => app(State::new()),
    }
}

async fn http(app: &Router, target: &str, body: &[u8]) -> (StatusCode, Bytes) {
    let request = Request::builder()
        .method("POST")
        .uri(target)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_vec()))
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("served");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, body)
}

async fn http_compress(app: &Router) -> (Vec<u8>, Value) {
    let envelope = serde_json::json!({
        "payload": String::from_utf8(payload()).expect("utf8"),
        "options": {"reversible": true},
    });
    let (status, body) = http(
        app,
        "/v1/compress?envelope=json",
        &serde_json::to_vec(&envelope).expect("json"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let answer: Value = serde_json::from_slice(&body).expect("envelope json");
    let compressed = answer["payload"]
        .as_str()
        .expect("payload")
        .as_bytes()
        .to_vec();
    (compressed, answer["stats"].clone())
}

fn percent_encode(id: &str) -> String {
    id.bytes()
        .map(|byte| match byte {
            b'0'..=b'9' | b'a'..=b'z' => (byte as char).to_string(),
            other => format!("%{other:02x}"),
        })
        .collect()
}

fn ids(stats: &Value) -> Vec<String> {
    stats["restore_ids"]
        .as_array()
        .expect("the envelope always carries the list")
        .iter()
        .map(|id| id.as_str().expect("a string id").to_string())
        .collect()
}

fn service(store: Option<Arc<dyn RootStore>>) -> grpc::Service {
    match store {
        Some(store) => grpc::Service::with_store(store),
        None => grpc::Service::new(),
    }
}

fn client(service: grpc::Service) -> CompressorClient<tonic::service::Routes> {
    CompressorClient::new(grpc::routes(service))
}

#[tokio::test]
async fn http_and_grpc_restore_the_same_original_for_the_same_id() {
    let store: Option<Arc<dyn RootStore>> = shared_store();
    if !CCR_ENABLED {
        assert!(store.is_none());
        let (status, body) = http(
            &router(None),
            "/v1/restore?restore_id=00000000000000000000000000000000:0",
            b"{}",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).expect("json")["error"]["code"],
            "not_implemented"
        );
        let mut client = client(service(None));
        let status = client
            .restore(RestoreRequest {
                payload: Vec::new(),
                restore_id: "00000000000000000000000000000000:0".to_string(),
            })
            .await
            .expect_err("disabled in this build");
        assert_eq!(status.code(), Code::Unimplemented);
        return;
    }

    let (http_compressed, http_stats) = http_compress(&router(store.clone())).await;
    let mut client = client(service(store.clone()));
    let answer = client
        .compress(compress_request())
        .await
        .expect("compress")
        .into_inner();
    assert_eq!(
        answer.payload, http_compressed,
        "the transports return the same bytes"
    );
    let served = answer.stats.expect("stats");
    assert_eq!(served.groups_collapsed, 2);
    let reported = ids(&http_stats);
    assert_eq!(served.restore_ids, reported, "one id per group, same order");
    assert_eq!(reported.len(), 2);
    assert_ne!(reported[0], reported[1]);

    for id in &reported {
        let original = client
            .restore(RestoreRequest {
                payload: http_compressed.clone(),
                restore_id: id.clone(),
            })
            .await
            .expect("a hit")
            .into_inner()
            .original;
        let (status, body) = http(
            &router(store.clone()),
            &format!("/v1/restore?restore_id={id}"),
            &http_compressed,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), original.as_slice(), "{id} restores alike");
        let envelope = serde_json::json!({
            "payload": String::from_utf8_lossy(&http_compressed),
            "restore_id": id,
        });
        let (status, body) = http(
            &router(store.clone()),
            "/v1/restore?envelope=json",
            &serde_json::to_vec(&envelope).expect("json"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), original.as_slice(), "{id} envelope form");
        assert!(
            payload()
                .windows(original.len())
                .any(|window| window == original.as_slice()),
            "the original is a slice of the input"
        );
    }
}

#[tokio::test]
async fn both_compress_shapes_store_the_same_originals() {
    if !CCR_ENABLED {
        return;
    }
    let store = Arc::new(ccr::Shared::default());
    let erased: Arc<dyn RootStore> = store.clone();
    let (status, body) = http(
        &router(Some(erased.clone())),
        "/v1/compress?reversible=true",
        &payload(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        store.len(),
        2,
        "the bare path stores what it compresses away"
    );
    let bare = body.as_ref().to_vec();
    let (compressed, stats) = http_compress(&router(Some(erased))).await;
    assert_eq!(compressed, bare, "the shapes return the same bytes");
    assert_eq!(store.len(), 2, "the same content, the same entry");
    for id in ids(&stats) {
        let (status, body) = http(
            &router(Some(Arc::new(ccr::Shared::default()))),
            &format!("/v1/restore?restore_id={id}"),
            &compressed,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a store of its own holds nothing"
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&body).expect("json")["error"]["code"],
            "not_found"
        );
    }
}

#[tokio::test]
async fn a_tampered_id_is_a_miss_on_both_transports() {
    if !CCR_ENABLED {
        return;
    }
    let store = shared_store();
    let (compressed, stats) = http_compress(&router(store.clone())).await;
    let reported = ids(&stats);
    let id = reported[0].clone();
    let (hash, len) = id.split_once(':').expect("one colon");
    let flipped = {
        let last = id.chars().last().expect("a hex digit");
        let other = if last == '0' { '1' } else { '0' };
        id.replace(last, &other.to_string())
    };
    let garbage = [
        String::new(),
        String::from("garbage"),
        format!("{id} "),
        id.replace(':', ""),
        format!("{}:{}", &hash[..31], len),
        format!("{hash}:{}", len.parse::<usize>().expect("a length") + 1),
        format!("{}:{}", hash.to_uppercase(), len),
        format!("{hash}:0{len}"),
    ];
    let mut client = client(service(store.clone()));
    for bad in garbage {
        let status = client
            .restore(RestoreRequest {
                payload: compressed.clone(),
                restore_id: bad.clone(),
            })
            .await
            .expect_err("a miss");
        assert_eq!(status.code(), Code::NotFound, "{bad}");
        let envelope = serde_json::json!({
            "payload": String::from_utf8_lossy(&compressed),
            "restore_id": bad,
        });
        let (status, body) = http(
            &router(store.clone()),
            "/v1/restore?envelope=json",
            &serde_json::to_vec(&envelope).expect("json"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).expect("json")["error"]["code"],
            "not_found"
        );
    }
    for well_formed in [
        "00000000000000000000000000000000:0".to_string(),
        flipped.clone(),
    ] {
        let (status, body) = http(
            &router(store.clone()),
            &format!("/v1/restore?restore_id={}", percent_encode(&well_formed)),
            &compressed,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{well_formed}");
        assert_eq!(
            serde_json::from_slice::<Value>(&body).expect("json")["error"]["code"],
            "not_found"
        );
    }
    let (status, _) = http(&router(store.clone()), "/v1/restore", &compressed).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no restore_id at all");
    let (status, _) = http(
        &router(store.clone()),
        "/v1/restore?nope=1&restore_id=x",
        &compressed,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "an unknown query key");
}

#[tokio::test]
async fn a_store_that_never_saw_a_compress_answers_a_miss() {
    if !CCR_ENABLED {
        return;
    }
    let store: Arc<dyn RootStore> = Arc::new(ccr::Shared::new(60, 1 << 20));
    let mut client = client(service(Some(store.clone())));
    let answer = client
        .compress(compress_request())
        .await
        .expect("compress")
        .into_inner();
    let id = answer.stats.expect("stats").restore_ids;
    assert_eq!(id.len(), 2, "the ids are still reported");
    let miss = client
        .restore(RestoreRequest {
            payload: answer.payload,
            restore_id: id[0].clone(),
        })
        .await
        .expect_err("a bound of sixty bytes holds nothing");
    assert_eq!(miss.code(), Code::NotFound);
    let (status, _) = http(
        &router(Some(store)),
        &format!("/v1/restore?restore_id={}", id[0]),
        b"{}",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_unwired_state_and_service_still_refuse_restore() {
    if !CCR_ENABLED {
        return;
    }
    let app = app(State::without_store());
    let answer = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/v1/restore?restore_id=00000000000000000000000000000000:0")
            .body(Body::from("{}"))
            .expect("request"),
    );
    let response = answer.await.expect("served");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).expect("json")["error"]["code"],
        "not_implemented"
    );
    let _ = http_compress(&app).await;
}

#[test]
fn the_restore_store_trait_is_the_one_seam_both_transports_use() {
    fn accepts<S: RestoreStore + ?Sized>(_: &S) {}
    let store = ccr::Shared::default();
    accepts(&store);
    let erased: Arc<dyn RootStore> = Arc::new(store);
    accepts(erased.as_ref());
    assert_eq!(
        std::any::type_name::<dyn RootStore>(),
        std::any::type_name::<dyn grpc::RestoreStore>()
    );
}
