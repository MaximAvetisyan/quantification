use std::net::SocketAddr;
use std::process::ExitCode;

use quantification_server::{SHUTDOWN_GRACE_MS, State, grpc, serve, shared_store, shutdown_grace};
use tokio::net::TcpListener;

const HTTP: &str = "QUANT_HTTP_ADDR";
const GRPC: &str = "QUANT_GRPC_ADDR";

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("quantification: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let address = std::env::var(HTTP).unwrap_or_else(|_| "127.0.0.1:8080".into());
    let grpc_address: SocketAddr = std::env::var(GRPC)
        .unwrap_or_else(|_| "127.0.0.1:50051".into())
        .parse()?;
    let grace = shutdown_grace(std::env::var(SHUTDOWN_GRACE_MS).ok().as_deref())?;
    let listener = TcpListener::bind(&address).await?;
    let bound = listener.local_addr()?;
    let store = shared_store();
    let state = match &store {
        Some(store) => State::with_store(store.clone()),
        None => State::new(),
    };
    let service = match store {
        Some(store) => grpc::Service::with_store(store),
        None => grpc::Service::new(),
    };
    eprintln!(
        "quantification listening on http://{bound} and grpc://{grpc_address} \
         (draining for {}ms on SIGTERM/SIGINT)",
        grace.as_millis()
    );
    match serve(listener, state, service, grpc_address, signalled(), grace).await {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => {
            eprintln!("quantification: {error}");
            Ok(ExitCode::from(error.exit_code()))
        }
    }
}

#[cfg(unix)]
async fn signalled() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(error) => {
            eprintln!("quantification: no SIGTERM handler, SIGTERM kills the process: {error}");
            return std::future::pending().await;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => eprintln!("quantification: SIGINT, draining"),
        _ = terminate.recv() => eprintln!("quantification: SIGTERM, draining"),
    }
}

#[cfg(not(unix))]
async fn signalled() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("quantification: ctrl-c, draining");
}
