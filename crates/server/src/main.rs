//! RefMD API Server entry point
//!
//! This is the Composition Root - where all dependencies are wired together.

mod adapters;
mod bootstrap;
mod config;
mod middleware_builders;

use axum::http::HeaderName;
use axum::{Json, Router, extract::State, routing::get};
use infrastructure::PgPool;
use infrastructure::{DatabaseConfig, RedisConfig, RedisPool, create_pool, create_redis_pool};
use presentation::{ApiDoc, routes};

use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
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

async fn health_check(
    State(state): State<HealthState>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
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

    let http_status = match overall_status {
        "unhealthy" => axum::http::StatusCode::SERVICE_UNAVAILABLE,
        _ => axum::http::StatusCode::OK,
    };

    (http_status, Json(status))
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
    let cluster_enabled = config::is_cluster_enabled();
    if cluster_enabled {
        tracing::info!("Cluster mode ENABLED - using Redis for shared state");
    } else {
        tracing::info!("Single-node mode - using in-memory state");
    }

    // Connect to database
    let db_config = DatabaseConfig::from_env()?;
    let pool = create_pool(&db_config).await?;
    tracing::info!("Connected to database");

    // Connect to Redis if cluster mode is enabled
    let redis: Option<(RedisPool, String)> = if cluster_enabled {
        let redis_config = RedisConfig::from_env()
            .ok_or_else(|| anyhow::anyhow!("REDIS_URL is required when CLUSTER_ENABLED=true"))?;
        let url = redis_config.url.clone();
        let pool = create_redis_pool(&redis_config).await?;
        tracing::info!("Connected to Redis");
        Some((pool, url))
    } else {
        None
    };

    // Load server secret (32 bytes for HMAC operations)
    let server_secret = config::load_server_secret()?;

    // Build all repositories, runtime stores, and application state
    let pool_arc = Arc::new(pool);
    let state = bootstrap::build_app_state(pool_arc.clone(), &redis, server_secret);

    // Create health check state (keeps Redis pool in server layer)
    let health_state = HealthState {
        db_pool: (*pool_arc).clone(),
        cluster_enabled,
        redis_pool: redis.as_ref().map(|(pool, _)| pool.clone()),
    };

    // PoP (Proof of Possession) headers for device authentication
    let pop_device_id = HeaderName::from_static("x-pop-device-id");
    let pop_challenge = HeaderName::from_static("x-pop-challenge");
    let pop_signature = HeaderName::from_static("x-pop-signature");

    let cors = middleware_builders::build_cors(&pop_device_id, &pop_challenge, &pop_signature)?;

    // Build application
    let enable_swagger = config::is_swagger_enabled();
    let security_headers = middleware_builders::build_security_headers(enable_swagger);

    let app = Router::new()
        .route("/health", get(health_check).with_state(health_state))
        .merge(routes::create_routes(state)?);

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

    // Warn about client IP header trust requirements
    presentation::client_ip::warn_if_no_trusted_proxy();

    tracing::info!("Starting server on {}", addr);
    if enable_swagger {
        tracing::info!("Swagger UI available at http://{}:{}/api/docs", host, port);
    }

    let listener = TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
