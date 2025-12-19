use axum::extract::{DefaultBodyLimit, MatchedPath};
use axum::extract::FromRef;
use axum::{Router, middleware, routing::get};
use http::HeaderValue;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use utoipa_swagger_ui::SwaggerUi;

use crate::config::Config;
use presentation::context::{AppContext, IdentityContext};
use presentation::openapi::ApiDoc;
use utoipa::OpenApi;

pub async fn build_api_router(cfg: &Config, ctx: AppContext) -> anyhow::Result<Router> {
    let cors = build_cors(cfg)?;
    let identity_ctx = IdentityContext::from_ref(&ctx);

    // Ensure uploads dir exists even when using S3 backend (local staging is still required)
    if let Err(e) = tokio::fs::create_dir_all(&cfg.storage_root).await {
        tracing::warn!(error=?e, dir=%cfg.storage_root, "Failed to create uploads dir");
    }

    // Build upload router with state
    let upload_router = Router::new()
        .route(
            "/*path",
            get(presentation::http::documents::files::serve_upload),
        )
        .with_state(ctx.clone());

    // Build API router
    let api_router = Router::new()
        .nest(
            "/api",
            presentation::http::core::health::routes(ctx.clone()),
        )
        .nest("/api", presentation::http::documents::routes(ctx.clone()))
        .nest(
            "/api/auth",
            presentation::http::identity::auth::routes(ctx.clone()),
        )
        .nest(
            "/api",
            presentation::http::documents::sharing::routes(ctx.clone()),
        )
        .nest(
            "/api",
            presentation::http::documents::files::routes(ctx.clone()),
        )
        .nest(
            "/api",
            presentation::http::documents::tagging::routes(ctx.clone()),
        )
        .nest("/api", presentation::http::git::routes(ctx.clone()))
        .nest(
            "/api",
            presentation::http::core::markdown::routes(ctx.clone()),
        )
        .nest("/api", presentation::http::plugins::routes(ctx.clone()))
        .nest(
            "/api",
            presentation::http::identity::api_tokens::routes(ctx.clone()),
        )
        .nest(
            "/api",
            presentation::http::core::storage_ingest::routes(ctx.clone()),
        )
        .nest("/api", presentation::http::workspaces::routes(ctx.clone()))
        .nest(
            "/api",
            presentation::http::identity::shortcuts::routes(ctx.clone()),
        )
        .nest(
            "/api/public",
            presentation::http::documents::publishing::routes(ctx.clone()),
        )
        .merge(SwaggerUi::new("/api/docs").url("/api/openapi.json", ApiDoc::openapi()))
        .layer(middleware::from_fn_with_state(
            identity_ctx.clone(),
            presentation::http::identity::auth::refresh_middleware,
        ))
        .layer(middleware::from_fn(
            presentation::http::identity::auth::request_status::middleware,
        ))
        .layer(cors)
        // Global body size limit for uploads (configurable)
        .layer(DefaultBodyLimit::max(cfg.upload_max_bytes))
        .layer(
            TraceLayer::new_for_http().make_span_with(|req: &http::Request<_>| {
                let method = req.method().clone();
                let uri = req.uri().clone();
                let matched = req
                    .extensions()
                    .get::<MatchedPath>()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default();
                tracing::info_span!("http", %method, %uri, matched_path = %matched)
            }),
        );

    let metrics_router = Router::new()
        .route(
            "/metrics",
            get(presentation::http::core::metrics::metrics_handler),
        )
        .with_state(ctx.clone());
    let api_router = api_router.merge(metrics_router);

    let api_router = api_router.nest("/api/uploads", upload_router);

    Ok(api_router)
}

pub fn build_ws_router(ctx: AppContext) -> Router {
    let identity_ctx = IdentityContext::from_ref(&ctx);
    Router::new()
        .route(
            "/api/yjs/:id",
            get(presentation::ws::documents::yjs::axum_ws_entry),
        )
        .with_state(ctx.clone())
        .layer(middleware::from_fn_with_state(
            identity_ctx.clone(),
            presentation::http::identity::auth::refresh_middleware,
        ))
        .layer(middleware::from_fn(
            presentation::http::identity::auth::request_status::middleware,
        ))
}

fn build_cors(cfg: &Config) -> anyhow::Result<CorsLayer> {
    let frontend_origin = if let Some(origin) = cfg.frontend_url.clone() {
        Some(HeaderValue::from_str(&origin).map_err(|_| {
            anyhow::anyhow!("FRONTEND_URL must be a valid origin (e.g., https://app.example.com)")
        })?)
    } else {
        None
    };

    let cors_allow_headers = [
        http::header::CONTENT_TYPE,
        http::header::AUTHORIZATION,
        http::header::HeaderName::from_static("x-workspace-id"),
    ];
    let cors_expose_headers = [http::header::WWW_AUTHENTICATE];
    let cors = if let Some(origin) = frontend_origin.clone() {
        CorsLayer::new()
            .allow_origin(origin)
            .allow_methods([
                http::Method::GET,
                http::Method::POST,
                http::Method::PUT,
                http::Method::DELETE,
                http::Method::PATCH,
                http::Method::OPTIONS,
            ])
            .allow_headers(cors_allow_headers.clone())
            .expose_headers(cors_expose_headers.clone())
            .allow_credentials(true)
    } else if cfg.is_production {
        // In production, FRONTEND_URL is mandatory (enforced earlier), but fallback defensively to deny all
        CorsLayer::new()
            .allow_origin(AllowOrigin::exact(HeaderValue::from_static("http://invalid")))
            .allow_methods([
                http::Method::GET,
                http::Method::POST,
                http::Method::PUT,
                http::Method::DELETE,
                http::Method::PATCH,
                http::Method::OPTIONS,
            ])
            .allow_headers(cors_allow_headers.clone())
            .expose_headers(cors_expose_headers.clone())
    } else {
        // Development convenience
        CorsLayer::new()
            .allow_origin(AllowOrigin::mirror_request())
            .allow_methods([
                http::Method::GET,
                http::Method::POST,
                http::Method::PUT,
                http::Method::DELETE,
                http::Method::PATCH,
                http::Method::OPTIONS,
            ])
            .allow_headers(cors_allow_headers.clone())
            .expose_headers(cors_expose_headers.clone())
            .allow_credentials(true)
    };
    Ok(cors)
}
