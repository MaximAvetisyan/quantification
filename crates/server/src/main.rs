use quantification_server::{State, app};

const ADDRESS: &str = "QUANT_HTTP_ADDR";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = std::env::var(ADDRESS).unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = tokio::net::TcpListener::bind(&address).await?;
    let bound = listener.local_addr()?;
    eprintln!("quantification listening on http://{bound}");
    axum::serve(listener, app(State::new())).await?;
    Ok(())
}
