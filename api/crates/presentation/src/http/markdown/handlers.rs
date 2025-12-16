use std::collections::HashMap;

use axum::{Json, extract::State, http::StatusCode};
use uuid::Uuid;

use application::services::errors::ServiceError;
use application::services::markdown::RenderOptions;
use application::services::markdown_render::MarkdownRenderTask;
use crate::context::AppContext;
use crate::http::auth::Bearer;

use super::types::{RenderManyRequest, RenderManyResponse, RenderRequest, RenderResponseBody};
use super::user_scope::resolve_user_scope_from_inputs;

#[utoipa::path(post, path = "/api/markdown/render", tag = "Markdown",
    request_body = RenderRequest,
    responses((status = 200, body = RenderResponseBody)))]
pub async fn render_markdown(
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Json(req): Json<RenderRequest>,
) -> Result<Json<RenderResponseBody>, StatusCode> {
    // Per-item size guard (2MB)
    if req.text.len() > 2 * 1024 * 1024 {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let RenderRequest { text, options } = req;
    let options: RenderOptions = options.into();

    let bearer_token = bearer.as_ref().map(|b| b.0.as_str());
    let user_scope =
        resolve_user_scope_from_inputs(&ctx, bearer_token, options.token.as_deref()).await;

    let renderer = ctx.markdown_renderer();
    let resp = renderer
        .render_single(text, options, user_scope)
        .await
        .map_err(map_markdown_error)?;
    Ok(Json(RenderResponseBody::from(resp)))
}

#[utoipa::path(post, path = "/api/markdown/render-many", tag = "Markdown",
    request_body = RenderManyRequest,
    responses((status = 200, body = RenderManyResponse)))]
pub async fn render_markdown_many(
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Json(req): Json<RenderManyRequest>,
) -> Result<Json<RenderManyResponse>, StatusCode> {
    // Guard: item count and total size
    const MAX_ITEMS: usize = 128;
    const MAX_TOTAL_BYTES: usize = 5 * 1024 * 1024; // 5MB
    let items = req.items;
    if items.len() > MAX_ITEMS {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let total: usize = items.iter().map(|i| i.text.len()).sum();
    if total > MAX_TOTAL_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let bearer_token = bearer.as_ref().map(|b| b.0.clone());
    let bearer_scope = resolve_user_scope_from_inputs(&ctx, bearer_token.as_deref(), None).await;
    let mut share_scope_cache: HashMap<String, Option<Uuid>> = HashMap::new();
    let mut tasks = Vec::with_capacity(items.len());

    for item in items {
        if item.text.len() > 2 * 1024 * 1024 {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        let RenderRequest { text, options } = item;
        let options: RenderOptions = options.into();
        let user_scope = if bearer_scope.is_some() {
            bearer_scope
        } else if let Some(token) = options.token.as_deref() {
            if let Some(scope) = share_scope_cache.get(token) {
                *scope
            } else {
                let scope = resolve_user_scope_from_inputs(&ctx, None, Some(token)).await;
                share_scope_cache.insert(token.to_string(), scope);
                scope
            }
        } else {
            None
        };
        tasks.push(MarkdownRenderTask {
            text,
            options,
            user_scope,
        });
    }

    let renderer = ctx.markdown_renderer();
    let responses = renderer
        .render_many(tasks)
        .await
        .map_err(map_markdown_error)?;
    let items = responses
        .into_iter()
        .map(RenderResponseBody::from)
        .collect();
    Ok(Json(RenderManyResponse { items }))
}

fn map_markdown_error(err: ServiceError) -> StatusCode {
    match err {
        ServiceError::Unauthorized | ServiceError::TokenExpired => StatusCode::UNAUTHORIZED,
        ServiceError::Forbidden => StatusCode::FORBIDDEN,
        ServiceError::Conflict => StatusCode::CONFLICT,
        ServiceError::NotFound => StatusCode::NOT_FOUND,
        ServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
        ServiceError::Unexpected(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
