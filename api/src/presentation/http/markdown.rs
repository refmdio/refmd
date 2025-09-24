use std::collections::HashMap;

use crate::application::services::markdown::{PlaceholderItem, RenderOptions, RenderResponse};
use crate::bootstrap::app_context::AppContext;
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde::{Deserialize, Serialize};
use tracing::warn;
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
    State(ctx): State<AppContext>,
    Json(req): Json<RenderRequest>,
) -> Result<Json<RenderResponseBody>, StatusCode> {
    // Per-item size guard (2MB)
    if req.text.len() > 2 * 1024 * 1024 {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let RenderRequest { text, options } = req;
    let options: RenderOptions = options.into();
    let mut resp = crate::application::services::markdown::render(text, options.clone())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !resp.placeholders.is_empty() {
        if let Err(err) = apply_placeholder_renderers(&ctx, &mut resp, &options).await {
            warn!(error = ?err, "markdown_placeholder_render_failed");
        }
    }
    Ok(Json(RenderResponseBody::from(resp)))
}

#[utoipa::path(post, path = "/api/markdown/render-many", tag = "Markdown",
    request_body = RenderManyRequest,
    responses((status = 200, body = RenderManyResponse)))]
pub async fn render_markdown_many(
    State(ctx): State<AppContext>,
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
        let options: RenderOptions = options.into();
        let mut res = crate::application::services::markdown::render(text, options.clone())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if !res.placeholders.is_empty() {
            if let Err(err) = apply_placeholder_renderers(&ctx, &mut res, &options).await {
                warn!(error = ?err, "markdown_placeholder_render_failed_many");
            }
        }
        out.push(RenderResponseBody::from(res));
    }
    Ok(Json(RenderManyResponse { items: out }))
}

struct RendererSpec {
    kind: String,
    plugin_id: String,
    function: String,
}

#[derive(Deserialize)]
struct RendererPluginResponse {
    ok: bool,
    html: Option<String>,
    error: Option<String>,
    warnings: Option<Vec<String>>,
}

async fn apply_placeholder_renderers(
    ctx: &AppContext,
    response: &mut RenderResponse,
    options: &RenderOptions,
) -> anyhow::Result<()> {
    let runtime = ctx.plugin_runtime();
    let assets = ctx.plugin_assets();

    let specs = collect_renderer_specs(assets.as_ref()).await?;
    if specs.is_empty() {
        return Ok(());
    }

    let mut html = response.html.clone();
    let mut remaining: Vec<PlaceholderItem> = Vec::new();
    let mut kind_map: HashMap<&str, Vec<&RendererSpec>> = HashMap::new();
    for spec in &specs {
        kind_map.entry(spec.kind.as_str()).or_default().push(spec);
    }

    let placeholders = std::mem::take(&mut response.placeholders);
    for placeholder in placeholders {
        let candidates = kind_map
            .get(placeholder.kind.as_str())
            .cloned()
            .unwrap_or_default();
        if candidates.is_empty() {
            remaining.push(placeholder);
            continue;
        }

        let mut handled = false;
        for spec in candidates {
            let request = build_renderer_request(&placeholder, options);
            match runtime
                .render_placeholder(None, &spec.plugin_id, &spec.function, &request)
                .await
            {
                Ok(Some(value)) => match serde_json::from_value::<RendererPluginResponse>(value) {
                    Ok(resp) if resp.ok => {
                        if let Some(warnings) = resp.warnings {
                            for message in warnings {
                                warn!(
                                    plugin = spec.plugin_id.as_str(),
                                    kind = placeholder.kind.as_str(),
                                    id = placeholder.id.as_str(),
                                    warning = message.as_str(),
                                    "placeholder_renderer_warning"
                                );
                            }
                        }
                        if let Some(fragment) = resp.html {
                            if replace_placeholder_markup(&mut html, &placeholder.id, &fragment) {
                                handled = true;
                                break;
                            }
                        }
                    }
                    Ok(resp) => {
                        if let Some(err) = resp.error {
                            warn!(
                                plugin = spec.plugin_id.as_str(),
                                kind = placeholder.kind.as_str(),
                                id = placeholder.id.as_str(),
                                error = err.as_str(),
                                "placeholder_renderer_error"
                            );
                        }
                    }
                    Err(err) => {
                        warn!(
                            plugin = spec.plugin_id.as_str(),
                            kind = placeholder.kind.as_str(),
                            id = placeholder.id.as_str(),
                            error = ?err,
                            "placeholder_renderer_parse_failed"
                        );
                    }
                },
                Ok(None) => {
                    continue;
                }
                Err(err) => {
                    warn!(
                        plugin = spec.plugin_id.as_str(),
                        kind = placeholder.kind.as_str(),
                        id = placeholder.id.as_str(),
                        error = ?err,
                        "placeholder_renderer_call_failed"
                    );
                }
            }
        }

        if !handled {
            remaining.push(placeholder);
        }
    }

    response.html = html;
    response.placeholders = remaining;
    Ok(())
}

fn build_renderer_request(
    placeholder: &PlaceholderItem,
    options: &RenderOptions,
) -> serde_json::Value {
    let features = options.features.clone().unwrap_or_default();
    let doc_id = options.doc_id.map(|id| id.to_string());
    let token = options.token.clone();
    let base_origin = options.base_origin.clone();
    let flavor = options.flavor.clone();
    let theme = options.theme.clone();
    serde_json::json!({
        "kind": placeholder.kind,
        "id": placeholder.id,
        "code": placeholder.code,
        "options": {
            "doc_id": doc_id,
            "token": token,
            "base_origin": base_origin,
            "flavor": flavor,
            "theme": theme,
            "features": features,
        }
    })
}

async fn collect_renderer_specs(
    assets: &dyn crate::application::ports::plugin_asset_store::PluginAssetStore,
) -> anyhow::Result<Vec<RendererSpec>> {
    let manifests = assets.list_latest_global_manifests().await?;
    let mut specs = Vec::new();
    for (plugin_id, _version, manifest) in manifests {
        if let Some(items) = manifest.get("renderers").and_then(|v| v.as_array()) {
            for item in items {
                if let Some(kind) = item.get("kind").and_then(|v| v.as_str()) {
                    let function = item
                        .get("function")
                        .and_then(|v| v.as_str())
                        .unwrap_or("render");
                    specs.push(RendererSpec {
                        kind: kind.to_string(),
                        plugin_id: plugin_id.clone(),
                        function: function.to_string(),
                    });
                }
            }
        }
    }
    Ok(specs)
}

fn replace_placeholder_markup(target: &mut String, id: &str, replacement: &str) -> bool {
    let needle = format!("<div data-mermaid=\"{}\"></div>", id);
    if let Some(pos) = target.find(&needle) {
        target.replace_range(pos..pos + needle.len(), replacement);
        return true;
    }
    let needle_newline = format!("<div data-mermaid=\"{}\"></div>\n", id);
    if let Some(pos) = target.find(&needle_newline) {
        target.replace_range(pos..pos + needle_newline.len(), replacement);
        return true;
    }
    false
}
