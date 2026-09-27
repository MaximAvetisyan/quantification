use quantification_server::grpc;
use quantification_server::{State, app, shared_store};

const HTTP: &str = "QUANT_HTTP_ADDR";
const GRPC: &str = "QUANT_GRPC_ADDR";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = std::env::var(HTTP).unwrap_or_else(|_| "127.0.0.1:8080".into());
    let grpc_address = std::env::var(GRPC)
        .unwrap_or_else(|_| "127.0.0.1:50051".into())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(&address).await?;
    let bound = listener.local_addr()?;
    eprintln!("quantification listening on http://{bound} and grpc://{grpc_address}");
    let store = shared_store();
    let state = match &store {
        Some(store) => State::with_store(store.clone()),
        None => State::new(),
    };
    let service = match store {
        Some(store) => grpc::Service::with_store(store),
        None => grpc::Service::new(),
    };
    let http = async {
        axum::serve(listener, app(state))
            .await
            .map_err(std::io::Error::other)
    };
    let grpc = async {
        tonic::transport::Server::builder()
            .add_service(grpc::server(service))
            .serve(grpc_address)
            .await
            .map_err(std::io::Error::other)
    };
    tokio::try_join!(http, grpc)?;
    Ok(())
}
