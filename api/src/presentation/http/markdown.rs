use crate::application::services::markdown::{PlaceholderItem, RenderOptions, RenderResponse};
use crate::bootstrap::app_context::AppContext;
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
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
    State(_ctx): State<AppContext>,
    Json(req): Json<RenderRequest>,
) -> Result<Json<RenderResponseBody>, StatusCode> {
    // Per-item size guard (2MB)
    if req.text.len() > 2 * 1024 * 1024 {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let RenderRequest { text, options } = req;
    let resp = crate::application::services::markdown::render(text, options.into())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(RenderResponseBody::from(resp)))
}

#[utoipa::path(post, path = "/api/markdown/render-many", tag = "Markdown",
    request_body = RenderManyRequest,
    responses((status = 200, body = RenderManyResponse)))]
pub async fn render_markdown_many(
    State(_ctx): State<AppContext>,
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

    // Process sequentially (simple and safe). Could be parallelized if needed.
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if item.text.len() > 2 * 1024 * 1024 {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        let RenderRequest { text, options } = item;
        let res = crate::application::services::markdown::render(text, options.into())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        out.push(RenderResponseBody::from(res));
    }
    Ok(Json(RenderManyResponse { items: out }))
}
