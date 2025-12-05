use std::collections::HashMap;

use crate::application::access;
use crate::application::services::errors::ServiceError;
use crate::application::services::markdown::{PlaceholderItem, RenderOptions, RenderResponse};
use crate::application::services::markdown_render::MarkdownRenderTask;
use crate::presentation::context::AppContext;
use crate::presentation::http::auth::{self, Bearer};
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
// no bearer injection; renderer should receive token via options when needed

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/markdown/render", post(render_markdown))
        .route("/markdown/render-many", post(render_markdown_many))
        .with_state(ctx)
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema, Default)]
#[serde(default)]
pub struct RenderOptionsPayload {
    pub flavor: Option<String>,
    pub theme: Option<String>,
    pub features: Option<Vec<String>>,
    pub sanitize: Option<bool>,
    pub hardbreaks: Option<bool>,
    pub doc_id: Option<uuid::Uuid>,
    pub base_origin: Option<String>,
    pub absolute_attachments: Option<bool>,
    pub token: Option<String>,
}

impl From<RenderOptionsPayload> for RenderOptions {
    fn from(value: RenderOptionsPayload) -> Self {
        RenderOptions {
            flavor: value.flavor,
            theme: value.theme,
            features: value.features,
            sanitize: value.sanitize,
            hardbreaks: value.hardbreaks,
            doc_id: value.doc_id,
            base_origin: value.base_origin,
            absolute_attachments: value.absolute_attachments,
            token: value.token,
        }
    }
}

impl From<RenderOptions> for RenderOptionsPayload {
    fn from(value: RenderOptions) -> Self {
        Self {
            flavor: value.flavor,
            theme: value.theme,
            features: value.features,
            sanitize: value.sanitize,
            hardbreaks: value.hardbreaks,
            doc_id: value.doc_id,
            base_origin: value.base_origin,
            absolute_attachments: value.absolute_attachments,
            token: value.token,
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PlaceholderItemPayload {
    pub kind: String,
    pub id: String,
    pub code: String,
}

impl From<PlaceholderItem> for PlaceholderItemPayload {
    fn from(value: PlaceholderItem) -> Self {
        Self {
            kind: value.kind,
            id: value.id,
            code: value.code,
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RenderResponseBody {
    pub html: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub placeholders: Vec<PlaceholderItemPayload>,
    pub hash: String,
}

impl From<RenderResponse> for RenderResponseBody {
    fn from(value: RenderResponse) -> Self {
        Self {
            html: value.html,
            placeholders: value
                .placeholders
                .into_iter()
                .map(PlaceholderItemPayload::from)
                .collect(),
            hash: value.hash,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RenderRequest {
    text: String,
    #[serde(default)]
    options: RenderOptionsPayload,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RenderManyRequest {
    items: Vec<RenderRequest>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RenderManyResponse {
    items: Vec<RenderResponseBody>,
}

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

async fn resolve_user_scope_from_inputs(
    ctx: &AppContext,
    bearer_token: Option<&str>,
    share_token: Option<&str>,
) -> Option<Uuid> {
    if let Some(token) = bearer_token {
        if let Some(workspace_id) = ctx.auth_service().workspace_from_token_claim(token) {
            return Some(workspace_id);
        }
        if let Ok(Some(workspace_id)) = ctx.auth_service().workspace_from_token_async(token).await {
            return Some(workspace_id);
        }
        if let Ok(sub) = auth::validate_bearer_str(ctx, token).await {
            if let Ok(uid) = Uuid::parse_str(&sub) {
                if let Ok(workspaces) = ctx.workspace_service().list_for_user(uid).await {
                    if workspaces.is_empty() {
                        return None;
                    }
                    if let Some(default_ws) = workspaces.iter().find(|ws| ws.is_default) {
                        return Some(default_ws.id);
                    }
                    return Some(workspaces[0].id);
                }
            }
        }
    }
    if let Some(token) = share_token {
        // Share token: resolve its workspace for renderer so plugin manifests can be loaded.
        if let Some(actor) = auth::resolve_actor_from_token_str(ctx, token).await {
            match actor {
                access::Actor::User(uid) => {
                    if let Ok(workspaces) = ctx.workspace_service().list_for_user(uid).await {
                        if workspaces.is_empty() {
                            return None;
                        }
                        if let Some(default_ws) = workspaces.iter().find(|ws| ws.is_default) {
                            return Some(default_ws.id);
                        }
                        return Some(workspaces[0].id);
                    }
                }
                access::Actor::ShareToken(t) => {
                    if let Ok(Some((_share_id, _perm, exp, _doc_id, _typ, workspace_id))) =
                        ctx.share_service().resolve_share_context(&t).await
                    {
                        if exp.map(|e| e < chrono::Utc::now()).unwrap_or(false) {
                            return None;
                        }
                        return Some(workspace_id);
                    }
                }
                _ => {}
            }
        }
    }
    None
}
