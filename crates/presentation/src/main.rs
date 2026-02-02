//! RefMD API Server entry point

use axum::{Router, routing::get};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

async fn health_check() -> &'static str {
    "OK"
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,presentation=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Build application
    let app = Router::new()
        .route("/health", get(health_check))
        .layer(TraceLayer::new_for_http());

    // Start server
    let host = std::env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("SERVER_PORT").unwrap_or_else(|_| "3001".to_string());
    let addr: SocketAddr = format!("{host}:{port}").parse()?;

    tracing::info!("Starting server on {}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
