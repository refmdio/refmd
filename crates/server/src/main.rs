//! RefMD API Server entry point
//!
//! This is the Composition Root - where all dependencies are wired together.

use axum::{Router, routing::get};
use infrastructure::{create_pool, DatabaseConfig};
use infrastructure::identity::{PgUserRepository, PgSessionRepository, PgUserSettingsRepository};
use presentation::{ApiDoc, AppState, routes};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

async fn health_check() -> &'static str {
    "OK"
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,server=debug,presentation=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Connect to database
    let db_config = DatabaseConfig::from_env();
    let pool = create_pool(&db_config).await?;
    tracing::info!("Connected to database");

    // Create repositories (Dependency Injection)
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let session_repo = Arc::new(PgSessionRepository::new(pool.clone()));
    let user_settings_repo = Arc::new(PgUserSettingsRepository::new(pool));

    // Create application state
    let state = AppState::new(user_repo, session_repo, user_settings_repo);

    // Build application
    let app = Router::new()
        .route("/health", get(health_check))
        .merge(routes::create_routes(state))
        .merge(SwaggerUi::new("/api/docs").url("/api/openapi.json", ApiDoc::openapi()))
        .layer(TraceLayer::new_for_http());

    // Start server
    let host = std::env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("SERVER_PORT").unwrap_or_else(|_| "3001".to_string());
    let addr: SocketAddr = format!("{host}:{port}").parse()?;

    tracing::info!("Starting server on {}", addr);
    tracing::info!("Swagger UI available at http://{}:{}/api/docs", host, port);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
