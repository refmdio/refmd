//! RefMD API Server entry point
//!
//! This is the Composition Root - where all dependencies are wired together.

use axum::http::{HeaderName, HeaderValue, Method, header};
use axum::{Json, Router, extract::State, routing::get};
use infrastructure::PgPool;
use infrastructure::document::{PgDocumentRepository, PgDocumentUpdateRepository};
use infrastructure::encryption::{
    PgDeviceEncryptedUMKRepository, PgDeviceRepository, PgDocumentEncryptedKeyRepository,
    PgPendingDeviceRepository, PgUserEncryptedIdentityKeyRepository,
    PgUserEncryptedMasterKeyRepository, PgUserIdentityPublicKeyRepository,
    PgWorkspaceEncryptedKeyRepository,
};
use infrastructure::identity::{PgSessionRepository, PgUserRepository, PgUserSettingsRepository};
use infrastructure::workspace::{
    PgWorkspaceMemberRepository, PgWorkspaceRepository, PgWorkspaceRoleRepository,
};
use infrastructure::{DatabaseConfig, PgRegistrationService, create_pool};
use infrastructure::{RedisChallengeStore, RedisDeviceEventBus, RedisRecoveryChallengeStore};
use infrastructure::{RedisConfig, RedisPool, create_redis_pool};
use infrastructure::{RedisTransferNonceStore, RedisTransferStateStore};
use presentation::{
    ApiDoc, AppState, AppStateParams, InMemoryChallengeStore, InMemoryDeviceEventBus, routes,
};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// Health check state (separate from AppState for clean architecture)
#[derive(Clone)]
struct HealthState {
    db_pool: PgPool,
    cluster_enabled: bool,
    redis_pool: Option<RedisPool>,
}

async fn health_check(State(state): State<HealthState>) -> Json<serde_json::Value> {
    let mut overall_status = "healthy";

    let mut status = json!({
        "cluster_mode": state.cluster_enabled,
    });

    // Check database connectivity
    match state.db_pool.acquire().await {
        Ok(_) => {
            status["database"] = json!("connected");
        }
        Err(_) => {
            overall_status = "unhealthy"; // DB failure is critical
            status["database"] = json!("disconnected");
        }
    }

    // Check Redis connectivity (only in cluster mode)
    if let Some(ref pool) = state.redis_pool {
        match pool.health_check().await {
            Ok(_) => {
                status["redis"] = json!("connected");
            }
            Err(_) => {
                // Redis failure is degraded, but don't override unhealthy
                if overall_status == "healthy" {
                    overall_status = "degraded";
                }
                status["redis"] = json!("disconnected");
            }
        }
    }

    status["status"] = json!(overall_status);
    Json(status)
}

// =============================================================================
// Newtype wrapper for RedisDeviceEventBus
// (Composition Root bridges infrastructure and presentation layers)
// =============================================================================

use presentation::{DeviceEvent, DeviceEventPublisher, DeviceEventSubscriber};
use tokio::sync::broadcast;

/// Wrapper to implement presentation traits on infrastructure type
#[derive(Clone)]
struct RedisEventBusAdapter(Arc<RedisDeviceEventBus>);

#[async_trait::async_trait]
impl DeviceEventPublisher for RedisEventBusAdapter {
    async fn publish(&self, event: DeviceEvent) {
        self.0.publish(event).await
    }
}

impl DeviceEventSubscriber for RedisEventBusAdapter {
    fn subscribe(&self) -> broadcast::Receiver<DeviceEvent> {
        self.0.subscribe()
    }
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

/// Check if cluster mode is enabled via environment variable
fn is_cluster_enabled() -> bool {
    std::env::var("CLUSTER_ENABLED")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false)
}

/// Check if Swagger UI is enabled via environment variable
/// Defaults to false (disabled) for security in production
fn is_swagger_enabled() -> bool {
    std::env::var("ENABLE_SWAGGER")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false)
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

    // Check cluster mode
    let cluster_enabled = is_cluster_enabled();
    if cluster_enabled {
        tracing::info!("Cluster mode ENABLED - using Redis for shared state");
    } else {
        tracing::info!("Single-node mode - using in-memory state");
    }

    // Connect to database
    let db_config = DatabaseConfig::from_env();
    let pool = create_pool(&db_config).await?;
    tracing::info!("Connected to database");

    // Connect to Redis if cluster mode is enabled
    let (redis_pool, redis_url): (Option<RedisPool>, Option<String>) = if cluster_enabled {
        let redis_config = RedisConfig::from_env()
            .ok_or_else(|| anyhow::anyhow!("REDIS_URL is required when CLUSTER_ENABLED=true"))?;
        let url = redis_config.url.clone();
        let pool = create_redis_pool(&redis_config).await?;
        tracing::info!("Connected to Redis");
        (Some(pool), Some(url))
    } else {
        (None, None)
    };

    // Load server secret (32 bytes for HMAC operations)
    let server_secret = load_server_secret()?;

    // Create repositories (Dependency Injection)
    let pool_arc = Arc::new(pool);
    let user_repo = Arc::new(PgUserRepository::new((*pool_arc).clone()));
    let session_repo = Arc::new(PgSessionRepository::new((*pool_arc).clone()));
    let user_settings_repo = Arc::new(PgUserSettingsRepository::new((*pool_arc).clone()));
    let user_identity_public_key_repo =
        Arc::new(PgUserIdentityPublicKeyRepository::new((*pool_arc).clone()));
    let user_encrypted_master_key_repo =
        Arc::new(PgUserEncryptedMasterKeyRepository::new((*pool_arc).clone()));
    let user_encrypted_identity_key_repo = Arc::new(PgUserEncryptedIdentityKeyRepository::new(
        (*pool_arc).clone(),
    ));
    let workspace_repo = Arc::new(PgWorkspaceRepository::new((*pool_arc).clone()));
    let workspace_member_repo = Arc::new(PgWorkspaceMemberRepository::new((*pool_arc).clone()));
    let workspace_role_repo = Arc::new(PgWorkspaceRoleRepository::new((*pool_arc).clone()));
    let document_repo = Arc::new(PgDocumentRepository::new((*pool_arc).clone()));
    let document_update_repo = Arc::new(PgDocumentUpdateRepository::new((*pool_arc).clone()));
    let workspace_key_repo = Arc::new(PgWorkspaceEncryptedKeyRepository::new((*pool_arc).clone()));
    let document_key_repo = Arc::new(PgDocumentEncryptedKeyRepository::new((*pool_arc).clone()));
    let registration_service = Arc::new(PgRegistrationService::new(pool_arc.clone()));
    let device_repo = Arc::new(PgDeviceRepository::new((*pool_arc).clone()));
    let pending_device_repo = Arc::new(PgPendingDeviceRepository::new((*pool_arc).clone()));
    let device_encrypted_umk_repo =
        Arc::new(PgDeviceEncryptedUMKRepository::new((*pool_arc).clone()));

    // Determine if cookies should have Secure attribute
    // Default to true for production, can be disabled for local development
    let secure_cookies = std::env::var("SECURE_COOKIES")
        .map(|v| v.to_lowercase() != "false" && v != "0")
        .unwrap_or(true);

    if !secure_cookies {
        tracing::warn!("SECURE_COOKIES is disabled. This should only be used in development!");
    }

    // Create challenge store, recovery challenge store, transfer stores, and device event bus based on cluster mode
    let (
        challenge_store,
        recovery_challenge_store,
        transfer_nonce_store,
        transfer_state_store,
        device_event_bus,
    ): (
        Arc<dyn presentation::ChallengeStore>,
        Arc<dyn presentation::RecoveryChallengeStore>,
        Arc<dyn application::domain::TransferNonceStore>,
        Arc<dyn application::domain::TransferStateStore>,
        Arc<dyn presentation::DeviceEventBus>,
    ) = if let Some(ref redis) = redis_pool {
        // Cluster mode: use Redis-backed implementations
        let url = redis_url.clone().unwrap();
        let challenge_store = Arc::new(RedisChallengeStore::new(redis.clone()));
        let recovery_challenge_store =
            Arc::new(RedisRecoveryChallengeStore::new(redis.clone()));
        let transfer_nonce_store = Arc::new(RedisTransferNonceStore::new(redis.clone()));
        let transfer_state_store = Arc::new(RedisTransferStateStore::new(redis.clone()));
        let redis_bus = RedisDeviceEventBus::new(redis.clone(), url);
        let device_event_bus = Arc::new(RedisEventBusAdapter(redis_bus));
        (
            challenge_store,
            recovery_challenge_store,
            transfer_nonce_store,
            transfer_state_store,
            device_event_bus,
        )
    } else {
        // Single-node mode: use in-memory implementations
        let challenge_store = Arc::new(InMemoryChallengeStore::default());
        let recovery_challenge_store =
            Arc::new(presentation::InMemoryRecoveryChallengeStore::default());
        let transfer_nonce_store = Arc::new(presentation::InMemoryTransferNonceStore::default());
        let transfer_state_store = Arc::new(presentation::InMemoryTransferStateStore::default());
        let device_event_bus = Arc::new(InMemoryDeviceEventBus::new());
        (
            challenge_store,
            recovery_challenge_store,
            transfer_nonce_store,
            transfer_state_store,
            device_event_bus,
        )
    };

    // Create application state
    let state = AppState::new(AppStateParams {
        user_repo,
        session_repo,
        user_settings_repo,
        user_identity_public_key_repo,
        user_encrypted_master_key_repo,
        user_encrypted_identity_key_repo,
        workspace_repo,
        workspace_member_repo,
        workspace_role_repo,
        document_repo,
        document_update_repo,
        workspace_key_repo,
        document_key_repo,
        registration_service,
        device_repo,
        pending_device_repo,
        device_encrypted_umk_repo,
        device_event_bus,
        challenge_store,
        recovery_challenge_store,
        transfer_nonce_store,
        transfer_state_store,
        server_secret,
        secure_cookies,
        cluster_enabled,
    });

    // Create health check state (keeps Redis pool in server layer)
    let health_state = HealthState {
        db_pool: (*pool_arc).clone(),
        cluster_enabled,
        redis_pool,
    };

    // CORS configuration for development
    // In production, this should be restricted to specific origins
    let cors_origins =
        std::env::var("CORS_ORIGINS").unwrap_or_else(|_| "http://localhost:3000".to_string());

    // Validate CORS origins - reject wildcard with credentials
    // Check for '*' anywhere in the list (not just as sole value)
    for origin in cors_origins.split(',') {
        if origin.trim() == "*" {
            anyhow::bail!(
                "CORS_ORIGINS contains '*' which is not allowed with credentials. Specify explicit origins (e.g., 'http://localhost:3000')."
            );
        }
    }

    let origins: Vec<_> = cors_origins
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    // Ensure at least one valid origin was parsed
    if origins.is_empty() {
        anyhow::bail!(
            "CORS_ORIGINS contains no valid origins. Specify at least one valid origin URL."
        );
    }

    // PoP (Proof of Possession) headers for device authentication
    let pop_device_id = HeaderName::from_static("x-pop-device-id");
    let pop_challenge = HeaderName::from_static("x-pop-challenge");
    let pop_signature = HeaderName::from_static("x-pop-signature");

    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::COOKIE,
            pop_device_id.clone(),
            pop_challenge.clone(),
            pop_signature.clone(),
        ])
        .expose_headers([pop_device_id, pop_challenge, pop_signature])
        .allow_credentials(true);

    // Build application
    let enable_swagger = is_swagger_enabled();

    // CSP varies based on Swagger UI enablement
    // Swagger UI requires inline scripts/styles, so we relax CSP when enabled
    let csp_value = if enable_swagger {
        // Relaxed CSP for Swagger UI (development only)
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'",
        )
    } else {
        // Strict CSP for production
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'")
    };

    // Security headers middleware
    let security_headers = ServiceBuilder::new()
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            csp_value,
        ));
    let app = Router::new()
        .route("/health", get(health_check).with_state(health_state))
        .merge(routes::create_routes(state));

    let app = if enable_swagger {
        app.merge(SwaggerUi::new("/api/docs").url("/api/openapi.json", ApiDoc::openapi()))
    } else {
        app
    };

    let app = app
        .layer(cors)
        .layer(security_headers)
        .layer(TraceLayer::new_for_http());

    // Start server
    let host = std::env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("SERVER_PORT").unwrap_or_else(|_| "8000".to_string());
    let addr: SocketAddr = format!("{host}:{port}").parse()?;

    tracing::info!("Starting server on {}", addr);
    if enable_swagger {
        tracing::info!("Swagger UI available at http://{}:{}/api/docs", host, port);
    }

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
