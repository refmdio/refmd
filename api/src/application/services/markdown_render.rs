use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::warn;
use uuid::Uuid;

use crate::application::ports::plugin_asset_store::PluginAssetStore;
use crate::application::ports::plugin_installation_repository::PluginInstallationRepository;
use crate::application::ports::plugin_runtime::PluginRuntime;
use crate::application::services::errors::ServiceError;
use crate::application::services::markdown::{
    PlaceholderItem, RenderOptions, RenderResponse, render,
};
use crate::application::services::plugins::asset_signer::{AssetScope, AssetSigner};

#[derive(Clone, Debug)]
pub struct MarkdownRenderTask {
    pub text: String,
    pub options: RenderOptions,
    pub user_scope: Option<Uuid>,
}

pub struct MarkdownRenderService {
    assets: Arc<dyn PluginAssetStore>,
    installations: Arc<dyn PluginInstallationRepository>,
    runtime: Arc<dyn PluginRuntime>,
    asset_signer: Arc<AssetSigner>,
    asset_ttl_secs: u64,
}

impl MarkdownRenderService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        assets: Arc<dyn PluginAssetStore>,
        installations: Arc<dyn PluginInstallationRepository>,
        runtime: Arc<dyn PluginRuntime>,
        asset_signer: Arc<AssetSigner>,
        asset_ttl_secs: u64,
    ) -> Self {
        Self {
            assets,
            installations,
            runtime,
            asset_signer,
            asset_ttl_secs,
        }
    }

    pub async fn render_single(
        &self,
        text: String,
        options: RenderOptions,
        user_scope: Option<Uuid>,
    ) -> Result<RenderResponse, ServiceError> {
        let specs = self.collect_renderer_specs(user_scope).await?;
        self.render_with_specs(text, options, specs.as_slice())
            .await
    }

    pub async fn render_many(
        &self,
        tasks: Vec<MarkdownRenderTask>,
    ) -> Result<Vec<RenderResponse>, ServiceError> {
        let mut spec_cache: HashMap<Option<Uuid>, Arc<Vec<RendererSpec>>> = HashMap::new();
        let mut results = Vec::with_capacity(tasks.len());
        for task in tasks {
            let specs = if let Some(existing) = spec_cache.get(&task.user_scope) {
                existing.clone()
            } else {
                let loaded = Arc::new(self.collect_renderer_specs(task.user_scope).await?);
                spec_cache.insert(task.user_scope, loaded.clone());
                loaded
            };
            results.push(
                self.render_with_specs(task.text, task.options, specs.as_slice())
                    .await?,
            );
        }
        Ok(results)
    }

    async fn render_with_specs(
        &self,
        text: String,
        options: RenderOptions,
        specs: &[RendererSpec],
    ) -> Result<RenderResponse, ServiceError> {
        let placeholder_kinds: HashSet<String> =
            specs.iter().map(|spec| spec.kind.clone()).collect();
        let placeholder_kinds_ref = if placeholder_kinds.is_empty() {
            None
        } else {
            Some(&placeholder_kinds)
        };

        let mut response =
            render(text, options.clone(), placeholder_kinds_ref).map_err(ServiceError::from)?;
        if !response.placeholders.is_empty() && !specs.is_empty() {
            self.apply_placeholder_renderers(&mut response, &options, specs)
                .await?;
        }
        Ok(response)
    }

    async fn collect_renderer_specs(
        &self,
        user_scope: Option<Uuid>,
    ) -> Result<Vec<RendererSpec>, ServiceError> {
        let mut specs = Vec::new();
        let manifests = self
            .assets
            .list_latest_global_manifests()
            .await
            .map_err(ServiceError::from)?;
        for (plugin_id, version, manifest) in manifests {
            push_renderers_from_manifest(
                &mut specs,
                &manifest,
                &plugin_id,
                &version,
                RendererScope::Global,
            );
        }

        if let Some(workspace_id) = user_scope {
            let installs = self
                .installations
                .list_for_workspace(workspace_id)
                .await
                .map_err(ServiceError::from)?;
            for inst in installs.into_iter().filter(|i| i.status == "enabled") {
                match self
                    .assets
                    .load_user_manifest(&workspace_id, &inst.plugin_id, &inst.version)
                    .await
                {
                    Ok(Some(manifest)) => push_renderers_from_manifest(
                        &mut specs,
                        &manifest,
                        &inst.plugin_id,
                        &inst.version,
                        RendererScope::Workspace { workspace_id },
                    ),
                    Ok(None) => {}
                    Err(err) => warn!(
                        error = ?err,
                        workspace_id = %workspace_id,
                        plugin = inst.plugin_id.as_str(),
                        version = inst.version.as_str(),
                        "workspace_renderer_manifest_load_failed"
                    ),
                }
            }
        }

        Ok(specs)
    }

    async fn apply_placeholder_renderers(
        &self,
        response: &mut RenderResponse,
        options: &RenderOptions,
        specs: &[RendererSpec],
    ) -> Result<(), ServiceError> {
        if specs.is_empty() {
            return Ok(());
        }

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
                let hydrate = spec.hydrate.as_ref();

                let Some(function) = spec.function.as_deref() else {
                    if let Some(hydrate) = hydrate {
                        if self.attach_hydrate_metadata(
                            &mut html,
                            &placeholder,
                            &request,
                            spec,
                            hydrate,
                            options.token.as_deref(),
                        ) {
                            handled = true;
                            break;
                        }
                    }
                    continue;
                };

                let user_scope = match &spec.scope {
                    RendererScope::Global => None,
                    RendererScope::Workspace { workspace_id } => Some(*workspace_id),
                };

                match self
                    .runtime
                    .render_placeholder(user_scope, &spec.plugin_id, function, &request)
                    .await
                {
                    Ok(Some(value)) => {
                        match serde_json::from_value::<RendererPluginResponse>(value) {
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
                                    let fragment = if let Some(hydrate) = hydrate {
                                        match self.build_hydrated_fragment(
                                            &placeholder,
                                            &request,
                                            spec,
                                            hydrate,
                                            options.token.as_deref(),
                                            &fragment,
                                        ) {
                                            Ok(wrapped) => wrapped,
                                            Err(err) => {
                                                warn!(
                                                    plugin = spec.plugin_id.as_str(),
                                                    kind = placeholder.kind.as_str(),
                                                    id = placeholder.id.as_str(),
                                                    error = ?err,
                                                    "placeholder_hydrate_metadata_failed"
                                                );
                                                fragment
                                            }
                                        }
                                    } else {
                                        fragment
                                    };

                                    if replace_placeholder_markup(
                                        &mut html,
                                        &placeholder.id,
                                        &fragment,
                                    ) {
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
                        }
                    }
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

    fn attach_hydrate_metadata(
        &self,
        target: &mut String,
        placeholder: &PlaceholderItem,
        request: &Value,
        spec: &RendererSpec,
        hydrate: &HydrateSpec,
        token: Option<&str>,
    ) -> bool {
        let attrs = match self.build_hydrate_attr_string(request, spec, hydrate, token) {
            Ok(value) => value,
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

        insert_placeholder_attributes(target, &placeholder.id, &attrs)
    }

    fn build_hydrated_fragment(
        &self,
        placeholder: &PlaceholderItem,
        request: &Value,
        spec: &RendererSpec,
        hydrate: &HydrateSpec,
        token: Option<&str>,
        fragment: &str,
    ) -> Result<String, serde_json::Error> {
        let attrs = self.build_hydrate_attr_string(request, spec, hydrate, token)?;
        Ok(format!(
            "<div data-refmd-placeholder=\"true\" data-placeholder-id=\"{}\" data-placeholder-kind=\"{}\"{}>{}</div>",
            htmlescape::encode_minimal(&placeholder.id),
            htmlescape::encode_minimal(&placeholder.kind),
            attrs,
            fragment
        ))
    }

    fn build_hydrate_attr_string(
        &self,
        request: &Value,
        spec: &RendererSpec,
        hydrate: &HydrateSpec,
        token: Option<&str>,
    ) -> Result<String, serde_json::Error> {
        let module_url = self
            .build_hydrate_module_url(spec, hydrate, token)
            .ok_or_else(|| {
                serde_json::Error::io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "invalid hydrate module path",
                ))
            })?;
        let export_name = hydrate.export.as_deref().unwrap_or("default");
        let context = json!({
            "request": request,
            "plugin": {
                "id": spec.plugin_id,
                "version": spec.plugin_version,
                "scope": spec.scope.as_str(),
            }
        });
        let context_str = serde_json::to_string(&context)?;
        let context_b64 = BASE64_STANDARD.encode(context_str);

        Ok(format!(
            " data-placeholder-hydrate=\"{}\" data-placeholder-hydrate-export=\"{}\" data-placeholder-hydrate-context=\"{}\" data-placeholder-plugin=\"{}\" data-placeholder-version=\"{}\" data-placeholder-scope=\"{}\"",
            htmlescape::encode_minimal(&module_url),
            htmlescape::encode_minimal(export_name),
            htmlescape::encode_minimal(&context_b64),
            htmlescape::encode_minimal(&spec.plugin_id),
            htmlescape::encode_minimal(&spec.plugin_version),
            htmlescape::encode_minimal(spec.scope.as_str()),
        ))
    }

    fn build_hydrate_module_url(
        &self,
        spec: &RendererSpec,
        hydrate: &HydrateSpec,
        token: Option<&str>,
    ) -> Option<String> {
        let module = hydrate.module.as_str();
        let scope = match spec.scope {
            RendererScope::Global => AssetScope::Global,
            RendererScope::Workspace { workspace_id } => AssetScope::User {
                owner_id: workspace_id,
                share_token: token,
            },
        };
        Some(self.asset_signer.sign_url(
            scope,
            &spec.plugin_id,
            &spec.plugin_version,
            module,
            self.asset_ttl_secs,
        ))
    }
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
enum RendererScope {
    Global,
    Workspace { workspace_id: Uuid },
}

impl RendererScope {
    fn as_str(&self) -> &'static str {
        match self {
            RendererScope::Global => "global",
            RendererScope::Workspace { .. } => "workspace",
        }
    }
}

#[derive(Clone, Debug)]
struct HydrateSpec {
    module: String,
    export: Option<String>,
    #[allow(dead_code)]
    etag: Option<String>,
}

#[derive(Deserialize)]
struct RendererPluginResponse {
    ok: bool,
    html: Option<String>,
    error: Option<String>,
    warnings: Option<Vec<String>>,
}

fn push_renderers_from_manifest(
    specs: &mut Vec<RendererSpec>,
    manifest: &Value,
    plugin_id: &str,
    version: &str,
    scope: RendererScope,
) {
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
                    plugin_id: plugin_id.to_string(),
                    plugin_version: version.to_string(),
                    scope: scope.clone(),
                    function,
                    hydrate,
                });
            }
        }
    }
}

fn build_renderer_request(placeholder: &PlaceholderItem, options: &RenderOptions) -> Value {
    let features = options.features.clone().unwrap_or_default();
    let doc_id = options.doc_id.map(|id| id.to_string());
    let token = options.token.clone();
    let base_origin = options.base_origin.clone();
    let flavor = options.flavor.clone();
    let theme = options.theme.clone();
    json!({
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

    if !remainder[..close_tag_offset].contains("data-refmd-placeholder=\"true\"") {
        return false;
    }

    let Some(close_div_offset) = target[open_tag_end..].find("</div>") else {
        return false;
    };
    let close_div_end = open_tag_end + close_div_offset + "</div>".len();

    let mut replace_end = close_div_end;
    if target[replace_end..].starts_with('\n') {
        replace_end += 1;
    }

    target.replace_range(open_start..replace_end, replacement);
    true
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
    let open_tag_end = open_start + close_tag_offset;

    target.insert_str(open_tag_end, attrs);
    true
}

fn parse_hydrate_spec(value: Option<&Value>) -> Option<HydrateSpec> {
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
