use std::collections::{HashMap, HashSet};

use crate::application::services::markdown::{PlaceholderItem, RenderOptions, RenderResponse};
use crate::bootstrap::app_context::AppContext;
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::warn;
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

    let assets = ctx.plugin_assets();
    let renderer_specs = match collect_renderer_specs(assets.as_ref()).await {
        Ok(specs) => specs,
        Err(err) => {
            warn!(error = ?err, "markdown_renderer_specs_failed");
            Vec::new()
        }
    };
    let placeholder_kinds: HashSet<String> = renderer_specs
        .iter()
        .map(|spec| spec.kind.clone())
        .collect();
    let placeholder_kinds_ref = if placeholder_kinds.is_empty() {
        None
    } else {
        Some(&placeholder_kinds)
    };

    let mut resp = crate::application::services::markdown::render(
        text,
        options.clone(),
        placeholder_kinds_ref,
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !resp.placeholders.is_empty() && !renderer_specs.is_empty() {
        if let Err(err) =
            apply_placeholder_renderers(&ctx, &mut resp, &options, &renderer_specs).await
        {
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

    let assets = ctx.plugin_assets();
    let renderer_specs = match collect_renderer_specs(assets.as_ref()).await {
        Ok(specs) => specs,
        Err(err) => {
            warn!(error = ?err, "markdown_renderer_specs_failed_many");
            Vec::new()
        }
    };
    let placeholder_kinds: HashSet<String> = renderer_specs
        .iter()
        .map(|spec| spec.kind.clone())
        .collect();
    let placeholder_kinds_ref = if placeholder_kinds.is_empty() {
        None
    } else {
        Some(&placeholder_kinds)
    };

    // Process sequentially (simple and safe). Could be parallelized if needed.
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if item.text.len() > 2 * 1024 * 1024 {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        let RenderRequest { text, options } = item;
        let options: RenderOptions = options.into();
        let mut res = crate::application::services::markdown::render(
            text,
            options.clone(),
            placeholder_kinds_ref,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if !res.placeholders.is_empty() && !renderer_specs.is_empty() {
            if let Err(err) =
                apply_placeholder_renderers(&ctx, &mut res, &options, &renderer_specs).await
            {
                warn!(error = ?err, "markdown_placeholder_render_failed_many");
            }
        }
        out.push(RenderResponseBody::from(res));
    }
    Ok(Json(RenderManyResponse { items: out }))
}

#[derive(Clone, Debug)]
struct RendererSpec {
    kind: String,
    plugin_id: String,
    plugin_version: String,
    scope: RendererScope,
    function: Option<String>,
    hydrate: Option<HydrateSpec>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
enum RendererScope {
    Global,
    User { user_id: Uuid },
}

impl RendererScope {
    fn as_str(&self) -> &'static str {
        match self {
            RendererScope::Global => "global",
            RendererScope::User { .. } => "user",
        }
    }

    fn asset_prefix(&self, plugin_id: &str, version: &str) -> String {
        match self {
            RendererScope::Global => {
                format!("/api/plugin-assets/global/{}/{}", plugin_id, version)
            }
            RendererScope::User { user_id } => {
                format!("/api/plugin-assets/{}/{}/{}", user_id, plugin_id, version)
            }
        }
    }
}

#[derive(Clone, Debug)]
struct HydrateSpec {
    module: String,
    export: Option<String>,
    etag: Option<String>,
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
    specs: &[RendererSpec],
) -> anyhow::Result<()> {
    if specs.is_empty() {
        return Ok(());
    }

    let runtime = ctx.plugin_runtime();

    let mut html = response.html.clone();
    let mut remaining: Vec<PlaceholderItem> = Vec::new();
    let mut kind_map: HashMap<&str, Vec<&RendererSpec>> = HashMap::new();
    for spec in specs {
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

            if let Some(hydrate) = &spec.hydrate {
                if attach_hydrate_metadata(&mut html, &placeholder, &request, spec, hydrate) {
                    handled = true;
                    break;
                }
                continue;
            }

            let Some(function) = spec.function.as_deref() else {
                continue;
            };

            match runtime
                .render_placeholder(None, &spec.plugin_id, function, &request)
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
                        } else {
                            warn!(
                                plugin = spec.plugin_id.as_str(),
                                kind = placeholder.kind.as_str(),
                                id = placeholder.id.as_str(),
                                "placeholder_renderer_missing_html"
                            );
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
    for (plugin_id, version, manifest) in manifests {
        if let Some(items) = manifest.get("renderers").and_then(|v| v.as_array()) {
            for item in items {
                if let Some(kind) = item.get("kind").and_then(|v| v.as_str()) {
                    let normalized_kind = kind.trim().to_lowercase();
                    if normalized_kind.is_empty() {
                        continue;
                    }
                    let hydrate = parse_hydrate_spec(item.get("hydrate"));
                    let mut function = item
                        .get("function")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string());
                    if function.is_none() && hydrate.is_none() {
                        function = Some("render".to_string());
                    }
                    specs.push(RendererSpec {
                        kind: normalized_kind,
                        plugin_id: plugin_id.clone(),
                        plugin_version: version.clone(),
                        scope: RendererScope::Global,
                        function,
                        hydrate,
                    });
                }
            }
        }
    }
    Ok(specs)
}

fn parse_hydrate_spec(value: Option<&serde_json::Value>) -> Option<HydrateSpec> {
    let obj = value?.as_object()?;
    let module_value = obj.get("module")?.as_str()?.trim();
    let module = sanitize_module_path(module_value)?;
    let export = obj
        .get("export")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let etag = obj
        .get("etag")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    Some(HydrateSpec {
        module,
        export,
        etag,
    })
}

fn sanitize_module_path(path: &str) -> Option<String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains("://") {
        return None;
    }
    let without_leading = trimmed.trim_start_matches('/');
    if without_leading.is_empty() {
        return None;
    }
    if without_leading
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return None;
    }
    Some(without_leading.to_string())
}

fn replace_placeholder_markup(target: &mut String, id: &str, replacement: &str) -> bool {
    let needle = format!("data-placeholder-id=\"{}\"", id);
    let Some(attr_pos) = target.find(&needle) else {
        return false;
    };

    let Some(open_start) = target[..attr_pos].rfind("<div") else {
        return false;
    };

    let remainder = &target[open_start..];
    let Some(close_tag_offset) = remainder.find('>') else {
        return false;
    };
    let open_tag_end = open_start + close_tag_offset + 1;

    // Simple guard to ensure we only replace placeholders rendered by the markdown service
    if !remainder[..close_tag_offset].contains("data-refmd-placeholder=\"true\"") {
        return false;
    }

    let Some(close_div_offset) = target[open_tag_end..].find("</div>") else {
        return false;
    };
    let close_div_end = open_tag_end + close_div_offset + "</div>".len();

    // Include a trailing newline to avoid leaving empty lines behind if one existed
    let mut replace_end = close_div_end;
    if target[replace_end..].starts_with('\n') {
        replace_end += 1;
    }

    target.replace_range(open_start..replace_end, replacement);
    true
}

fn attach_hydrate_metadata(
    target: &mut String,
    placeholder: &PlaceholderItem,
    request: &serde_json::Value,
    spec: &RendererSpec,
    hydrate: &HydrateSpec,
) -> bool {
    let module_url = build_hydrate_module_url(spec, hydrate);
    let export_name = hydrate.export.as_deref().unwrap_or("default");
    let context = json!({
        "request": request,
        "plugin": {
            "id": spec.plugin_id,
            "version": spec.plugin_version,
            "scope": spec.scope.as_str(),
        }
    });
    let context_str = match serde_json::to_string(&context) {
        Ok(v) => v,
        Err(err) => {
            warn!(
                plugin = spec.plugin_id.as_str(),
                kind = placeholder.kind.as_str(),
                id = placeholder.id.as_str(),
                error = ?err,
                "placeholder_hydrate_context_serialize_failed"
            );
            return false;
        }
    };
    let context_b64 = BASE64_STANDARD.encode(context_str);

    let attrs = format!(
        " data-placeholder-hydrate=\"{}\" data-placeholder-hydrate-export=\"{}\" data-placeholder-hydrate-context=\"{}\" data-placeholder-plugin=\"{}\" data-placeholder-version=\"{}\" data-placeholder-scope=\"{}\"",
        htmlescape::encode_minimal(&module_url),
        htmlescape::encode_minimal(export_name),
        htmlescape::encode_minimal(&context_b64),
        htmlescape::encode_minimal(&spec.plugin_id),
        htmlescape::encode_minimal(&spec.plugin_version),
        htmlescape::encode_minimal(spec.scope.as_str()),
    );

    insert_placeholder_attributes(target, &placeholder.id, &attrs)
}

fn build_hydrate_module_url(spec: &RendererSpec, hydrate: &HydrateSpec) -> String {
    let base = spec
        .scope
        .asset_prefix(&spec.plugin_id, &spec.plugin_version);
    let module_path = hydrate.module.trim_start_matches('/');
    let mut url = format!("{}/{}", base.trim_end_matches('/'), module_path);
    if let Some(etag) = &hydrate.etag {
        if !etag.is_empty() {
            let encoded = urlencoding::encode(etag);
            if url.contains('?') {
                url.push_str("&v=");
                url.push_str(&encoded);
            } else {
                url.push_str("?v=");
                url.push_str(&encoded);
            }
        }
    }
    url
}

fn insert_placeholder_attributes(target: &mut String, id: &str, attrs: &str) -> bool {
    let needle = format!("data-placeholder-id=\"{}\"", id);
    let Some(attr_pos) = target.find(&needle) else {
        return false;
    };

    let Some(open_start) = target[..attr_pos].rfind("<div") else {
        return false;
    };

    let remainder = &target[open_start..];
    let Some(close_tag_offset) = remainder.find('>') else {
        return false;
    };

    if remainder[..close_tag_offset].contains("data-placeholder-hydrate=\"") {
        return true;
    }

    if !remainder[..close_tag_offset].contains("data-refmd-placeholder=\"true\"") {
        return false;
    }

    let insert_pos = open_start + close_tag_offset;
    target.insert_str(insert_pos, attrs);
    true
}
