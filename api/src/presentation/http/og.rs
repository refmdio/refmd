use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use htmlescape::encode_minimal as escape_html;
use tracing::error;
use uuid::Uuid;

use crate::application::use_cases::public::og_preview::{GeneratePublicOgPreview, PublicOgPreview};
use crate::bootstrap::app_context::AppContext;

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/public/users/:name/:id", get(public_document_og))
        .with_state(ctx)
}

#[utoipa::path(
    get,
    path = "/api/og/public/users/{name}/{id}",
    tag = "OpenGraph",
    params(
        ("name" = String, Path, description = "Public profile name"),
        ("id" = Uuid, Path, description = "Public document ID")
    ),
    responses(
        (status = 200, description = "HTML page with OpenGraph metadata", body = String, content_type = "text/html"),
        (status = 404, description = "Document not found or not public"),
        (status = 500, description = "Failed to generate OpenGraph preview")
    )
)]
async fn public_document_og(
    State(ctx): State<AppContext>,
    Path((name, id)): Path<(String, Uuid)>,
) -> Result<Response, StatusCode> {
    let repo = ctx.public_repo();
    let realtime = ctx.realtime_port();
    let uc = GeneratePublicOgPreview {
        repo: repo.as_ref(),
        realtime: realtime.as_ref(),
    };

    let preview: PublicOgPreview = uc
        .execute(&name, id)
        .await
        .map_err(|err| {
            error!(owner = %name, document_id = %id, error = ?err, "public_og_generate_failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    let canonical_path = format!("/u/{}/{}", urlencoding::encode(&name), id);
    let canonical_url = absolute_frontend_url(&ctx, &canonical_path);
    let og_image_url = default_og_image(&ctx);
    let html = build_redirect_html(
        &preview.title,
        &preview.summary,
        &canonical_url,
        &og_image_url,
    );

    Ok(with_cache_headers(Html(html)))
}

fn build_redirect_html(title: &str, description: &str, canonical: &str, image: &str) -> String {
    let esc_title = escape_html(title);
    let esc_desc = escape_html(description);
    let esc_canonical = escape_html(canonical);
    let esc_image = escape_html(image);

    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\" />\n<title>{title}</title>\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n<meta name=\"description\" content=\"{desc}\" />\n<meta property=\"og:title\" content=\"{title}\" />\n<meta property=\"og:description\" content=\"{desc}\" />\n<meta property=\"og:type\" content=\"article\" />\n<meta property=\"og:url\" content=\"{canonical}\" />\n<meta property=\"og:image\" content=\"{image}\" />\n<meta name=\"twitter:card\" content=\"summary_large_image\" />\n<meta name=\"twitter:title\" content=\"{title}\" />\n<meta name=\"twitter:description\" content=\"{desc}\" />\n<meta name=\"twitter:image\" content=\"{image}\" />\n<link rel=\"canonical\" href=\"{canonical}\" />\n</head>\n<body>\n<script>setTimeout(function() {{ location.replace('{canonical}'); }}, 50);</script>\n<p>Redirecting to <a href=\"{canonical}\">{canonical}</a>…</p>\n</body>\n</html>\n",
        title = esc_title,
        desc = esc_desc,
        canonical = esc_canonical,
        image = esc_image,
    )
}

fn with_cache_headers(html: Html<String>) -> Response {
    let mut response = html.into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    response
}

fn absolute_frontend_url(ctx: &AppContext, path: &str) -> String {
    match ctx.cfg.frontend_url.as_deref() {
        Some(base) => format!("{}{}", base.trim_end_matches('/'), path),
        None => path.to_string(),
    }
}

fn default_og_image(ctx: &AppContext) -> String {
    match ctx.cfg.frontend_url.as_deref() {
        Some(base) => format!("{}{}", base.trim_end_matches('/'), "/refmd-512.png"),
        None => "/refmd-512.png".to_string(),
    }
}
