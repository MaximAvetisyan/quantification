use std::net::SocketAddr;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use quantification_core::api::{Compressor, Request as CoreRequest};
use quantification_server::{
    DEFAULT_SHUTDOWN_GRACE_MS, ENDPOINT_SETTLE_MS, SHUTDOWN_GRACE_MS, ServeError, State, app, grpc,
    serve, shutdown_grace,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tower::ServiceExt;

const PAYLOAD: &[u8] =
    br#"{"messages":[{"role":"user","content":"ERROR timeout\nERROR timeout\nERROR timeout\nERROR done"}]}"#;
const KUBERNETES_GRACE_SECONDS: u64 = 30;

struct Running {
    http: SocketAddr,
    state: State,
    trigger: Option<oneshot::Sender<()>>,
    done: JoinHandle<Result<(), ServeError>>,
}

impl Running {
    fn start(grace: Duration) -> Self {
        let (http, grpc_address, listener) = listeners();
        let state = State::new();
        let (trigger, wait) = oneshot::channel();
        let done = tokio::spawn(serve(
            listener,
            state.clone(),
            grpc::Service::new(),
            grpc_address,
            async {
                let _ = wait.await;
            },
            grace,
        ));
        Self {
            http,
            state,
            trigger: Some(trigger),
            done,
        }
    }

    fn signal(&mut self) {
        let trigger = self.trigger.take().expect("one signal per server");
        let _ = trigger.send(());
    }

    async fn finish(self) -> Result<(), ServeError> {
        self.done.await.expect("the server task joins")
    }
}

fn listeners() -> (SocketAddr, SocketAddr, TcpListener) {
    let (http, grpc_address) = (port(), port());
    let bound = std::net::TcpListener::bind(http).expect("bind http");
    bound.set_nonblocking(true).expect("nonblocking");
    let listener = TcpListener::from_std(bound).expect("tokio listener");
    (http, grpc_address, listener)
}

fn port() -> SocketAddr {
    use std::sync::atomic::{AtomicU16, Ordering};

    static NEXT: AtomicU16 = AtomicU16::new(0);
    let base = 20_000u16 + (std::process::id() as u16 % 4_000) * 2;
    let offset = NEXT.fetch_add(1, Ordering::SeqCst);
    format!("127.0.0.1:{}", base + offset)
        .parse()
        .expect("an address")
}

fn core(payload: &[u8]) -> Vec<u8> {
    let mut compressor = Compressor::new();
    let mut out = Vec::new();
    compressor
        .compress(payload, &CoreRequest::default(), &mut out)
        .expect("the core never fails these payloads");
    out
}

async fn get(app: &Router, target: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .uri(target)
        .body(Body::empty())
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("router answers");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&body).into_owned())
}

async fn compress(app: &Router) -> (Bytes, HeaderMap) {
    let request = Request::builder()
        .method("POST")
        .uri("/v1/compress")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(PAYLOAD.to_vec()))
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("router answers");
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (body, headers)
}

async fn read_response(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let split = loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            break None;
        }
        raw.extend_from_slice(&chunk[..read]);
        if let Some(at) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break Some(at + 4);
        }
    }?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let length: usize = head
        .lines()
        .filter_map(|line| line.split_once(": "))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())?;
    while raw.len() < split + length {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => raw.extend_from_slice(&chunk[..read]),
        }
    }
    Some((head, raw[split..].to_vec()))
}

async fn post_head(stream: &mut TcpStream, address: SocketAddr, body: &[u8]) {
    let head = format!(
        "POST /v1/compress HTTP/1.1\r\nhost: {address}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.expect("head");
}

async fn get_over_tcp(address: SocketAddr, target: &str) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(address).await.ok()?;
    let request = format!("GET {target} HTTP/1.1\r\nhost: {address}\r\nconnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.ok()?;
    let (head, body) = read_response(&mut stream).await?;
    let status = head
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some((status, String::from_utf8_lossy(&body).into_owned()))
}

async fn answers(address: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect(address).await else {
        return false;
    };
    let request = format!("GET /readyz HTTP/1.1\r\nhost: {address}\r\nconnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).await.is_err() {
        return false;
    }
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_millis(500), stream.read_to_end(&mut raw)).await;
    raw.starts_with(b"HTTP/1.1")
}

struct Server(Child);

impl Server {
    fn spawn(http: SocketAddr, grpc_address: SocketAddr, grace: &str) -> Self {
        let server = Command::new(env!("CARGO_BIN_EXE_quantification-server"))
            .env("QUANT_HTTP_ADDR", http.to_string())
            .env("QUANT_GRPC_ADDR", grpc_address.to_string())
            .env(SHUTDOWN_GRACE_MS, grace)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the server binary starts");
        Self(server)
    }

    fn terminate(&self) {
        assert_eq!(
            unsafe { libc::kill(self.0.id() as i32, libc::SIGTERM) },
            0,
            "SIGTERM is delivered"
        );
    }

    fn exit(&mut self) -> ExitStatus {
        self.0.wait().expect("the server exits")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn the_grace_period_is_configurable_and_fits_inside_the_kubernetes_deadline() {
    assert_eq!(SHUTDOWN_GRACE_MS, "QUANT_SHUTDOWN_GRACE_MS");
    assert_eq!(
        shutdown_grace(None).expect("unset means the default"),
        Duration::from_millis(DEFAULT_SHUTDOWN_GRACE_MS)
    );
    assert_eq!(
        shutdown_grace(Some("1500")).expect("milliseconds"),
        Duration::from_millis(1500)
    );
    assert_eq!(
        shutdown_grace(Some(" 1500 ")).expect("trimmed"),
        Duration::from_millis(1500)
    );
    assert_eq!(shutdown_grace(Some("0")).expect("zero"), Duration::ZERO);
    for raw in ["", "abc", "-1", "1.5", "25s", "1_000"] {
        assert!(
            shutdown_grace(Some(raw)).is_err(),
            "{raw:?} is not a whole number of milliseconds"
        );
    }
    const _: () = assert!(
        DEFAULT_SHUTDOWN_GRACE_MS > ENDPOINT_SETTLE_MS,
        "the default budget leaves room for the endpoint settle"
    );
    const _: () = assert!(
        DEFAULT_SHUTDOWN_GRACE_MS < KUBERNETES_GRACE_SECONDS * 1000,
        "terminationGracePeriodSeconds must sit above the drain budget"
    );
}

#[tokio::test]
async fn draining_takes_readyz_out_of_service_and_leaves_healthz_alone() {
    let state = State::new();
    let app = app(state.clone());
    assert_eq!(
        get(&app, "/readyz").await,
        (StatusCode::OK, "{\"status\":\"ready\"}".into())
    );
    assert_eq!(
        get(&app, "/healthz").await,
        (StatusCode::OK, "{\"status\":\"ok\"}".into())
    );

    state.drain();

    assert_eq!(
        get(&app, "/readyz").await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "{\"status\":\"draining\"}".into()
        ),
        "readiness is the endpoint signal, so it must fail while draining"
    );
    assert_eq!(
        get(&app, "/healthz").await,
        (StatusCode::OK, "{\"status\":\"ok\"}".into()),
        "liveness stays green or the kubelet restarts the pod mid-drain"
    );
    assert!(state.draining());
}

#[tokio::test]
async fn the_drain_leaves_the_output_bytes_untouched() {
    let state = State::new();
    let app = app(state.clone());
    let (before, before_headers) = compress(&app).await;
    state.drain();
    let (after, after_headers) = compress(&app).await;
    assert_eq!(after, core(PAYLOAD));
    assert_eq!(after, before, "draining is not an input to the compressor");
    assert_eq!(
        after_headers, before_headers,
        "and it moves no stats header"
    );
}

async fn latched(state: &State) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !state.draining() {
        assert!(
            Instant::now() < deadline,
            "the signal was sent, so the drain must latch"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_latched_shutdown_stops_accepting_and_exits_clean() {
    let mut running = Running::start(Duration::from_millis(1_000));
    assert!(!running.state.draining());
    let http = running.http;
    running.signal();

    assert!(
        running.finish().await.is_ok(),
        "a signal-initiated drain with no work in flight is a clean exit"
    );
    assert!(
        !answers(http).await,
        "and the listener is gone, so nothing new arrives"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_in_flight_finishes_during_the_drain() {
    let (http, grpc_address, listener) = listeners();
    let state = State::new();
    let (trigger, wait) = oneshot::channel();
    let done = tokio::spawn(serve(
        listener,
        state.clone(),
        grpc::Service::new(),
        grpc_address,
        async {
            let _ = wait.await;
        },
        Duration::from_millis(5_000),
    ));
    let mut stream = TcpStream::connect(http).await.expect("connect");
    post_head(&mut stream, http, PAYLOAD).await;
    stream
        .write_all(&PAYLOAD[..17])
        .await
        .expect("half the body");
    let _ = trigger.send(());

    latched(&state).await;
    assert!(
        !done.is_finished(),
        "the drain waits for the request that is already in flight"
    );

    stream.write_all(&PAYLOAD[17..]).await.expect("rest");
    let (head, body) = tokio::time::timeout(Duration::from_secs(5), read_response(&mut stream))
        .await
        .expect("the in-flight request is answered inside the grace")
        .expect("the in-flight request gets a whole response");
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    assert_eq!(
        body,
        core(PAYLOAD),
        "the drained request is byte for byte intact"
    );
    assert!(
        done.await.expect("the server task joins").is_ok(),
        "and the server exits zero once it is answered"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_grace_period_bounds_the_drain() {
    let (http, grpc_address, listener) = listeners();
    let (trigger, wait) = oneshot::channel();
    let done = tokio::spawn(serve(
        listener,
        State::new(),
        grpc::Service::new(),
        grpc_address,
        async {
            let _ = wait.await;
        },
        Duration::from_millis(200),
    ));
    let mut stream = TcpStream::connect(http).await.expect("connect");
    post_head(&mut stream, http, PAYLOAD).await;
    let _ = trigger.send(());
    let started = Instant::now();

    let served = tokio::time::timeout(Duration::from_secs(5), done)
        .await
        .expect("the drain is bounded, not open ended")
        .expect("the server task joins");
    let elapsed = started.elapsed();

    assert!(
        matches!(served, Err(ServeError::GraceExpired(budget)) if budget == Duration::from_millis(200)),
        "a body that never finishes is not a clean exit: {served:?}"
    );
    assert_eq!(
        ServeError::GraceExpired(Duration::ZERO).exit_code(),
        2,
        "an expired grace is its own exit code"
    );
    assert!(elapsed < Duration::from_millis(2_000), "{elapsed:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_transport_tears_down_the_other_and_exits_non_zero() {
    let grpc_address = port();
    let _squatter = std::net::TcpListener::bind(grpc_address).expect("bind");
    let (http, _, listener) = listeners();
    let state = State::new();

    let served = tokio::time::timeout(
        Duration::from_secs(5),
        serve(
            listener,
            state.clone(),
            grpc::Service::new(),
            grpc_address,
            std::future::pending(),
            Duration::from_millis(5_000),
        ),
    )
    .await
    .expect("the failure is reported, not a hang");

    let Err(error) = served else {
        panic!("a grpc port already in use is a failure: {served:?}");
    };
    assert!(
        matches!(error, ServeError::Grpc(_)),
        "the taken grpc port is the failure: {error}"
    );
    assert_eq!(error.exit_code(), 1);
    assert!(state.draining());
    assert!(
        !answers(http).await,
        "one dead transport takes the other down with it, so the pod is replaced whole"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sigterm_drains_and_exits_zero() {
    let (http, grpc_address) = (port(), port());
    let mut server = Server::spawn(http, grpc_address, "4000");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if get_over_tcp(http, "/readyz")
            .await
            .is_some_and(|(status, _)| status == 200)
        {
            break;
        }
        assert!(Instant::now() < deadline, "the server never became ready");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let started = Instant::now();
    server.terminate();
    let mut draining = false;
    while Instant::now() < deadline && !draining {
        if let Some((503, body)) = get_over_tcp(http, "/readyz").await {
            assert_eq!(body, "{\"status\":\"draining\"}");
            if let Some((200, live)) = get_over_tcp(http, "/healthz").await {
                assert_eq!(
                    live, "{\"status\":\"ok\"}",
                    "liveness stays green through the drain or the kubelet kills the pod"
                );
                draining = true;
            }
        }
        if !draining {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    assert!(
        draining,
        "readiness is withdrawn while liveness is still green"
    );
    assert!(
        answers(http).await,
        "the listener is still open while the endpoints are being removed"
    );

    let status = server.exit();
    let elapsed = started.elapsed();
    assert!(
        status.success(),
        "a signal-initiated drain exits zero: {status}"
    );
    assert!(elapsed < Duration::from_millis(4_000), "{elapsed:?}");
    assert!(!answers(http).await, "and the port stops answering");
}
