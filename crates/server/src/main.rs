//! RefMD API Server entry point
//!
//! This is the Composition Root - where all dependencies are wired together.

use axum::{Router, routing::get};
use axum::http::{header, Method};
use infrastructure::{create_pool, DatabaseConfig, PgRegistrationService};
use infrastructure::identity::{PgUserRepository, PgSessionRepository, PgUserSettingsRepository};
use infrastructure::encryption::{
    PgUserIdentityPublicKeyRepository, PgUserEncryptedMasterKeyRepository,
    PgUserEncryptedIdentityKeyRepository,
};
use infrastructure::workspace::{
    PgWorkspaceRepository, PgWorkspaceMemberRepository, PgWorkspaceRoleRepository,
};
use presentation::{ApiDoc, AppState, routes};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

async fn health_check() -> &'static str {
    "OK"
}

/// Load server secret from environment variable
/// SERVER_SECRET must be a 64-character hex string (32 bytes)
fn load_server_secret() -> anyhow::Result<[u8; 32]> {
    let secret_hex = std::env::var("SERVER_SECRET")
        .map_err(|_| anyhow::anyhow!("SERVER_SECRET environment variable is required"))?;

    if secret_hex.len() != 64 {
        return Err(anyhow::anyhow!(
            "SERVER_SECRET must be exactly 64 hex characters (32 bytes)"
        ));
    }

    let mut secret = [0u8; 32];
    hex::decode_to_slice(&secret_hex, &mut secret)
        .map_err(|e| anyhow::anyhow!("Invalid SERVER_SECRET hex encoding: {}", e))?;

    Ok(secret)
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

    // Load server secret (32 bytes for HMAC operations)
    let server_secret = load_server_secret()?;

    // Create repositories (Dependency Injection)
    let pool_arc = Arc::new(pool);
    let user_repo = Arc::new(PgUserRepository::new((*pool_arc).clone()));
    let session_repo = Arc::new(PgSessionRepository::new((*pool_arc).clone()));
    let user_settings_repo = Arc::new(PgUserSettingsRepository::new((*pool_arc).clone()));
    let user_identity_public_key_repo = Arc::new(PgUserIdentityPublicKeyRepository::new((*pool_arc).clone()));
    let user_encrypted_master_key_repo = Arc::new(PgUserEncryptedMasterKeyRepository::new((*pool_arc).clone()));
    let user_encrypted_identity_key_repo = Arc::new(PgUserEncryptedIdentityKeyRepository::new((*pool_arc).clone()));
    let workspace_repo = Arc::new(PgWorkspaceRepository::new((*pool_arc).clone()));
    let workspace_member_repo = Arc::new(PgWorkspaceMemberRepository::new((*pool_arc).clone()));
    let workspace_role_repo = Arc::new(PgWorkspaceRoleRepository::new((*pool_arc).clone()));
    let registration_service = Arc::new(PgRegistrationService::new(pool_arc));

    // Determine if cookies should have Secure attribute
    // Default to true for production, can be disabled for local development
    let secure_cookies = std::env::var("SECURE_COOKIES")
        .map(|v| v.to_lowercase() != "false" && v != "0")
        .unwrap_or(true);

    if !secure_cookies {
        tracing::warn!("SECURE_COOKIES is disabled. This should only be used in development!");
    }

    // Create application state
    let state = AppState::new(
        user_repo,
        session_repo,
        user_settings_repo,
        user_identity_public_key_repo,
        user_encrypted_master_key_repo,
        user_encrypted_identity_key_repo,
        workspace_repo,
        workspace_member_repo,
        workspace_role_repo,
        registration_service,
        server_secret,
        secure_cookies,
    );

    // CORS configuration for development
    // In production, this should be restricted to specific origins
    let cors_origins = std::env::var("CORS_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());

    let origins: Vec<_> = cors_origins
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::COOKIE])
        .allow_credentials(true);

    // Build application
    let app = Router::new()
        .route("/health", get(health_check))
        .merge(routes::create_routes(state))
        .merge(SwaggerUi::new("/api/docs").url("/api/openapi.json", ApiDoc::openapi()))
        .layer(cors)
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
