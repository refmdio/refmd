use axum::response::sse::{Event, KeepAlive, Sse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, patch, post},
};
use futures_util::stream::{self, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::application::access;
use crate::application::dto::plugins::ExecResult;
use crate::application::use_cases::plugins::exec_action::ExecutePluginAction;
use crate::application::use_cases::plugins::install_from_url::{
    InstallPluginError, InstallPluginFromUrl,
};
use crate::application::use_cases::plugins::kv::{GetPluginKv, PutPluginKv};
use crate::application::use_cases::plugins::records::{
    CreatePluginRecord, DeletePluginRecord, GetPluginRecord, ListPluginRecords, UpdatePluginRecord,
};
use crate::bootstrap::app_context::AppContext;
use crate::presentation::http::auth::{self, Bearer};

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        // Manifest for current user (stubbed)
        .route("/me/plugins/manifest", get(get_manifest))
        // SSE updates (stubbed)
        .route("/me/plugins/updates", get(sse_updates))
        // Generic exec endpoint
        .route("/plugins/:plugin/exec/:action", post(exec_action))
        .route("/me/plugins/install-from-url", post(install_from_url))
        .route("/me/plugins/uninstall", post(uninstall))
        // Generic records API
        .route(
            "/plugins/:plugin/docs/:doc_id/records/:kind",
            get(list_records).post(create_record),
        )
        .route(
            "/plugins/:plugin/records/:id",
            patch(update_record).delete(delete_record),
        )
        .route(
            "/plugins/:plugin/docs/:doc_id/kv/:key",
            get(get_kv_value).put(put_kv_value),
        )
        .with_state(ctx)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RecordsPath {
    plugin: String,
    doc_id: Uuid,
    kind: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RecordsResponse {
    items: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExecResultResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    pub effects: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<serde_json::Value>,
}

impl From<ExecResult> for ExecResultResponse {
    fn from(value: ExecResult) -> Self {
        Self {
            ok: value.ok,
            data: value.data,
            effects: value.effects,
            error: value.error,
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/plugins/{plugin}/docs/{doc_id}/records/{kind}",
    params(
        ("plugin" = String, Path, description = "Plugin ID"),
        ("doc_id" = Uuid, Path, description = "Document ID"),
        ("kind" = String, Path, description = "Record kind"),
        ("limit" = Option<i64>, Query, description = "Limit"),
        ("offset" = Option<i64>, Query, description = "Offset"),
        ("token" = Option<String>, Query, description = "Share token")
    ),
    responses((status = 200, body = RecordsResponse)),
    tag = "Plugins"
)]
pub async fn list_records(
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Query(params): Query<HashMap<String, String>>,
    Path(p): Path<RecordsPath>,
) -> Result<Json<RecordsResponse>, StatusCode> {
    let token = params.get("token").map(|s| s.as_str());
    let actor =
        auth::resolve_actor_from_parts(&ctx.cfg, bearer, token).ok_or(StatusCode::UNAUTHORIZED)?;
    // View permission required on doc
    let share_access = ctx.share_access_port();
    let access_repo = ctx.access_repo();
    access::require_view(
        access_repo.as_ref(),
        share_access.as_ref(),
        &actor,
        p.doc_id,
    )
    .await
    .map_err(|_| StatusCode::FORBIDDEN)?;

    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    let offset = params
        .get("offset")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0)
        .max(0);

    let repo = ctx.plugin_repo();
    let list_uc = ListPluginRecords {
        repo: repo.as_ref(),
    };
    let rows = list_uc
        .execute(&p.plugin, "doc", p.doc_id, &p.kind, limit, offset)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut items = Vec::with_capacity(rows.len());
    for r in rows {
        // Normalize output shape for client (id + data + timestamps)
        items.push(json!({
            "id": r.id,
            "plugin": r.plugin,
            "kind": r.kind,
            "data": r.data,
            "createdAt": r.created_at,
            "updatedAt": r.updated_at,
        }));
    }
    Ok(Json(RecordsResponse { items }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRecordBody {
    data: serde_json::Value,
}

#[utoipa::path(
    post,
    path = "/api/plugins/{plugin}/docs/{doc_id}/records/{kind}",
    request_body = CreateRecordBody,
    params(
        ("plugin" = String, Path, description = "Plugin ID"),
        ("doc_id" = Uuid, Path, description = "Document ID"),
        ("kind" = String, Path, description = "Record kind"),
        ("token" = Option<String>, Query, description = "Share token")
    ),
    responses((status = 200, body = serde_json::Value)),
    tag = "Plugins",
    operation_id = "pluginsCreateRecord"
)]
pub async fn create_record(
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Query(params): Query<HashMap<String, String>>,
    Path(p): Path<RecordsPath>,
    Json(body): Json<CreateRecordBody>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let token = params.get("token").map(|s| s.as_str());
    let actor =
        auth::resolve_actor_from_parts(&ctx.cfg, bearer, token).ok_or(StatusCode::UNAUTHORIZED)?;
    // Edit permission required on doc
    let share_access = ctx.share_access_port();
    let access_repo = ctx.access_repo();
    access::require_edit(
        access_repo.as_ref(),
        share_access.as_ref(),
        &actor,
        p.doc_id,
    )
    .await
    .map_err(|_| StatusCode::FORBIDDEN)?;

    // Attach authorId and timestamps if not provided
    let mut data = body.data;
    if let access::Actor::User(uid) = actor {
        data["authorId"] = json!(uid);
    }

    let repo = ctx.plugin_repo();
    let create_uc = CreatePluginRecord {
        repo: repo.as_ref(),
    };
    let rec = create_uc
        .execute(&p.plugin, "doc", p.doc_id, &p.kind, &data)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({
        "id": rec.id,
        "data": rec.data,
        "createdAt": rec.created_at,
        "updatedAt": rec.updated_at,
    })))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRecordPath {
    plugin: String,
    id: Uuid,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRecordBody {
    patch: serde_json::Value,
}

#[utoipa::path(
    patch,
    path = "/api/plugins/{plugin}/records/{id}",
    request_body = UpdateRecordBody,
    params(("plugin" = String, Path, description = "Plugin ID"), ("id" = Uuid, Path, description = "Record ID")),
    responses((status = 200, body = serde_json::Value)),
    tag = "Plugins",
    operation_id = "pluginsUpdateRecord"
)]
pub async fn update_record(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(p): Path<UpdateRecordPath>,
    Json(body): Json<UpdateRecordBody>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let repo = ctx.plugin_repo();
    // Get record for scope info and docId to enforce edit permission
    let get_uc = GetPluginRecord {
        repo: repo.as_ref(),
    };
    let rec = get_uc
        .execute(p.id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if rec.plugin != p.plugin {
        return Err(StatusCode::NOT_FOUND);
    }

    // Edit permission on the doc scope
    let share_access = ctx.share_access_port();
    let access_repo = ctx.access_repo();
    access::require_edit(
        access_repo.as_ref(),
        share_access.as_ref(),
        &access::Actor::User(user_id),
        rec.scope_id,
    )
    .await
    .map_err(|_| StatusCode::FORBIDDEN)?;

    let update_uc = UpdatePluginRecord {
        repo: repo.as_ref(),
    };
    let updated = update_uc
        .execute(p.id, &body.patch)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(json!({
        "id": updated.id,
        "data": updated.data,
        "updatedAt": updated.updated_at,
    })))
}

#[utoipa::path(
    delete,
    path = "/api/plugins/{plugin}/records/{id}",
    params(("plugin" = String, Path, description = "Plugin ID"), ("id" = Uuid, Path, description = "Record ID")),
    responses((status = 204)),
    tag = "Plugins",
    operation_id = "pluginsDeleteRecord"
)]
pub async fn delete_record(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(p): Path<UpdateRecordPath>,
) -> Result<StatusCode, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let repo = ctx.plugin_repo();
    // Get record to authorize
    let get_uc = GetPluginRecord {
        repo: repo.as_ref(),
    };
    let rec = get_uc
        .execute(p.id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if rec.plugin != p.plugin {
        return Err(StatusCode::NOT_FOUND);
    }

    let share_access = ctx.share_access_port();
    let access_repo = ctx.access_repo();
    access::require_edit(
        access_repo.as_ref(),
        share_access.as_ref(),
        &access::Actor::User(user_id),
        rec.scope_id,
    )
    .await
    .map_err(|_| StatusCode::FORBIDDEN)?;

    let delete_uc = DeletePluginRecord {
        repo: repo.as_ref(),
    };
    let ok = delete_uc
        .execute(p.id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if ok {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct KvPath {
    plugin: String,
    doc_id: Uuid,
    key: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct KvValueResponse {
    value: serde_json::Value,
}
#[derive(Debug, Deserialize, ToSchema)]
pub struct KvValueBody {
    value: serde_json::Value,
}

#[utoipa::path(
    get,
    path = "/api/plugins/{plugin}/docs/{doc_id}/kv/{key}",
    params(("plugin" = String, Path, description = "Plugin ID"), ("doc_id" = Uuid, Path, description = "Document ID"), ("key" = String, Path, description = "Key"), ("token" = Option<String>, Query, description = "Share token")),
    responses((status = 200, body = KvValueResponse)),
    tag = "Plugins",
    operation_id = "pluginsGetKv"
)]
pub async fn get_kv_value(
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Query(params): Query<HashMap<String, String>>,
    Path(p): Path<KvPath>,
) -> Result<Json<KvValueResponse>, StatusCode> {
    let token = params.get("token").map(|s| s.as_str());
    let actor =
        auth::resolve_actor_from_parts(&ctx.cfg, bearer, token).ok_or(StatusCode::UNAUTHORIZED)?;
    // View permission required on doc
    let share_access = ctx.share_access_port();
    let access_repo = ctx.access_repo();
    access::require_view(
        access_repo.as_ref(),
        share_access.as_ref(),
        &actor,
        p.doc_id,
    )
    .await
    .map_err(|_| StatusCode::FORBIDDEN)?;

    let repo = ctx.plugin_repo();
    let get_uc = GetPluginKv {
        repo: repo.as_ref(),
    };
    let val = get_uc
        .execute(&p.plugin, "doc", Some(p.doc_id), &p.key)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unwrap_or(serde_json::Value::Null);
    Ok(Json(KvValueResponse { value: val }))
}

#[utoipa::path(
    put,
    path = "/api/plugins/{plugin}/docs/{doc_id}/kv/{key}",
    request_body = KvValueBody,
    params(("plugin" = String, Path, description = "Plugin ID"), ("doc_id" = Uuid, Path, description = "Document ID"), ("key" = String, Path, description = "Key"), ("token" = Option<String>, Query, description = "Share token")),
    responses((status = 204)),
    tag = "Plugins",
    operation_id = "pluginsPutKv"
)]
pub async fn put_kv_value(
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Query(params): Query<HashMap<String, String>>,
    Path(p): Path<KvPath>,
    Json(body): Json<KvValueBody>,
) -> Result<StatusCode, StatusCode> {
    let token = params.get("token").map(|s| s.as_str());
    let actor =
        auth::resolve_actor_from_parts(&ctx.cfg, bearer, token).ok_or(StatusCode::UNAUTHORIZED)?;
    // Edit permission required on doc
    let share_access = ctx.share_access_port();
    let access_repo = ctx.access_repo();
    access::require_edit(
        access_repo.as_ref(),
        share_access.as_ref(),
        &actor,
        p.doc_id,
    )
    .await
    .map_err(|_| StatusCode::FORBIDDEN)?;

    let repo = ctx.plugin_repo();
    let put_uc = PutPluginKv {
        repo: repo.as_ref(),
    };
    put_uc
        .execute(&p.plugin, "doc", Some(p.doc_id), &p.key, &body.value)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ManifestItem {
    id: String,
    name: Option<String>,
    version: String,
    scope: String,
    mounts: Vec<String>,
    frontend: serde_json::Value,
    permissions: Vec<String>,
    config: serde_json::Value,
    ui: serde_json::Value,
    author: Option<String>,
    repository: Option<String>,
}

fn manifest_item_from_json(
    id: &str,
    version: &str,
    manifest: &serde_json::Value,
    entry_prefix: &str,
    scope: &str,
) -> Option<ManifestItem> {
    let name = manifest
        .get("name")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let mounts = manifest
        .get("mounts")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<String>>()
        })
        .unwrap_or_else(|| vec![format!("/{id}/*")]);

    let frontend_value = manifest.get("frontend");
    let (frontend_entry, frontend_mode) = match frontend_value {
        Some(v) => {
            let entry = v.get("entry").and_then(|x| x.as_str());
            let mode = v
                .get("mode")
                .and_then(|x| x.as_str())
                .unwrap_or("esm")
                .to_string();
            (entry.map(|e| e.to_string()), Some(mode))
        }
        None => (None, None),
    };

    let perms = manifest
        .get("permissions")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<String>>()
        })
        .unwrap_or_else(|| vec![]);

    let config = manifest.get("config").cloned().unwrap_or_else(|| json!({}));
    let ui = manifest.get("ui").cloned().unwrap_or_else(|| json!({}));
    let author = manifest
        .get("author")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let repository = manifest
        .get("repository")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());

    Some(ManifestItem {
        id: id.to_string(),
        name,
        version: version.to_string(),
        scope: scope.to_string(),
        mounts,
        frontend: match frontend_entry {
            Some(entry) => json!({
                "entry": format!("{}/{}", entry_prefix.trim_end_matches('/'), entry),
                "mode": frontend_mode.unwrap_or_else(|| "esm".to_string()),
            }),
            None => serde_json::Value::Null,
        },
        permissions: perms,
        config,
        ui,
        author,
        repository,
    })
}

#[utoipa::path(
    get,
    path = "/api/me/plugins/manifest",
    responses((status = 200, body = [ManifestItem])),
    tag = "Plugins",
    operation_id = "pluginsGetManifest"
)]
pub async fn get_manifest(
    State(ctx): State<AppContext>,
    bearer: Bearer,
) -> Result<Json<Vec<ManifestItem>>, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let store = ctx.plugin_assets();
    let mut items: Vec<ManifestItem> = Vec::new();

    let global_plugins = store
        .list_latest_global_manifests()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    for (id_name, ver, json) in global_plugins {
        if let Some(item) = manifest_item_from_json(
            &id_name,
            &ver,
            &json,
            &format!("/api/plugin-assets/global/{}/{}", id_name, ver),
            "global",
        ) {
            items.push(item);
        }
    }

    let installation_repo = ctx.plugin_installations();
    let installs = installation_repo
        .list_for_user(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    for inst in installs.into_iter().filter(|i| i.status == "enabled") {
        if let Some(json) = store
            .load_user_manifest(&user_id, &inst.plugin_id, &inst.version)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            if let Some(item) = manifest_item_from_json(
                &inst.plugin_id,
                &inst.version,
                &json,
                &format!(
                    "/api/plugin-assets/{}/{}/{}",
                    user_id, inst.plugin_id, inst.version
                ),
                "user",
            ) {
                items.push(item);
            }
        }
    }

    items.sort_by(|a, b| {
        let scope_order_a = if a.scope == "user" { 0 } else { 1 };
        let scope_order_b = if b.scope == "user" { 0 } else { 1 };
        scope_order_a
            .cmp(&scope_order_b)
            .then_with(|| a.id.cmp(&b.id))
            .then_with(|| a.version.cmp(&b.version))
    });
    Ok(Json(items))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ExecBody {
    payload: Option<serde_json::Value>,
}

#[utoipa::path(
    post,
    path = "/api/plugins/{plugin}/exec/{action}",
    request_body = ExecBody,
    params(("plugin" = String, Path, description = "Plugin ID"), ("action" = String, Path, description = "Action")),
    responses((status = 200, body = ExecResultResponse)),
    tag = "Plugins",
    operation_id = "pluginsExecAction"
)]
pub async fn exec_action(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path((plugin, action)): Path<(String, String)>,
    Json(body): Json<ExecBody>,
) -> Result<Json<ExecResultResponse>, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let plugin_repo = ctx.plugin_repo();
    let document_repo = ctx.document_repo();
    let runtime_store = ctx.plugin_runtime();
    let exec_uc = ExecutePluginAction {
        runtime: runtime_store.as_ref(),
        plugin_repo: plugin_repo.as_ref(),
        document_repo: document_repo.as_ref(),
    };

    match exec_uc
        .execute(user_id, &plugin, &action, body.payload.clone())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        Some(result) => Ok(Json(ExecResultResponse::from(result))),
        None => Ok(Json(ExecResultResponse {
            ok: false,
            data: None,
            effects: vec![],
            error: Some(json!({ "code": "UNKNOWN_ACTION" })),
        })),
    }
}

#[utoipa::path(
    get,
    path = "/api/me/plugins/updates",
    tag = "Plugins",
    responses((status = 200, description = "Plugin event stream", content_type = "text/event-stream"))
)]
pub async fn sse_updates(
    State(ctx): State<AppContext>,
    bearer: Bearer,
) -> Result<Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>>, StatusCode> {
    // authenticate user (per-user stream)
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let initial = stream::iter(vec![Ok(Event::default().event("ready").data("{}\n"))]);
    let broadcast = ctx.subscribe_plugin_events().filter_map(move |ev| {
        let user_id = user_id.clone();
        async move {
            if ev.user_id.is_some() && ev.user_id != Some(user_id) {
                return None;
            }
            let payload = ev.payload.to_string();
            Some(Ok(Event::default().event("update").data(payload)))
        }
    });
    let merged = initial.chain(broadcast);
    let keepalive = KeepAlive::new()
        .interval(Duration::from_secs(25))
        .text(":\n");
    Ok(Sse::new(merged).keep_alive(keepalive))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct InstallFromUrlBody {
    url: String,
    token: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct InstallResponse {
    id: String,
    version: String,
}

#[utoipa::path(
    post,
    path = "/api/me/plugins/install-from-url",
    request_body = InstallFromUrlBody,
    responses((status = 200, body = InstallResponse)),
    tag = "Plugins",
    operation_id = "pluginsInstallFromUrl"
)]
pub async fn install_from_url(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Json(body): Json<InstallFromUrlBody>,
) -> Result<Json<InstallResponse>, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx.cfg, bearer)?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let fetcher = ctx.plugin_fetcher();
    let installer = ctx.plugin_installer();
    let publisher = ctx.plugin_event_publisher();
    let installations = ctx.plugin_installations();
    let install_uc = InstallPluginFromUrl {
        fetcher: fetcher.as_ref(),
        installer: installer.as_ref(),
        events: publisher.as_ref(),
        installations: installations.as_ref(),
    };

    match install_uc
        .execute(user_id, &body.url, body.token.as_deref())
        .await
    {
        Ok(installed) => Ok(Json(InstallResponse {
            id: installed.id,
            version: installed.version,
        })),
        Err(err) => {
            tracing::error!(error = ?err, "failed to install plugin from url");
            match err {
                InstallPluginError::Download(_) => Err(StatusCode::BAD_GATEWAY),
                InstallPluginError::Install(inner) => match inner {
                    crate::application::ports::plugin_installer::PluginInstallError::InvalidPackage(_) => {
                        Err(StatusCode::BAD_REQUEST)
                    }
                    crate::application::ports::plugin_installer::PluginInstallError::Storage(_) => {
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                },
                InstallPluginError::Persist(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
                InstallPluginError::Event(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
            }
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UninstallBody {
    id: String,
}

#[utoipa::path(
    post,
    path = "/api/me/plugins/uninstall",
    request_body = UninstallBody,
    responses((status = 204)),
    tag = "Plugins",
    operation_id = "pluginsUninstall"
)]
pub async fn uninstall(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Json(body): Json<UninstallBody>,
) -> Result<StatusCode, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx.cfg, bearer)?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    // For global plugins, uninstall endpoint no longer updates per-user list.
    // Optionally we could implement deletion from disk by id+version (not done here).
    let installations = ctx.plugin_installations();
    let _ = installations.remove(user_id, &body.id).await;

    let store = ctx.plugin_assets();
    let plugin_id_for_remove = body.id.clone();
    let store_for_remove = store.clone();
    let user_id_for_remove = user_id;
    match tokio::task::spawn_blocking(move || {
        store_for_remove.remove_user_plugin_dir(&user_id_for_remove, &plugin_id_for_remove)
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(err)) => tracing::warn!(error = ?err, "plugin_uninstall_cleanup_failed"),
        Err(err) => tracing::warn!(error = ?err, "plugin_uninstall_cleanup_join_failed"),
    }

    let publisher = ctx.plugin_event_publisher();
    let event = crate::application::ports::plugin_event_publisher::PluginScopedEvent {
        user_id: Some(user_id),
        payload: json!({ "event": "uninstalled", "id": body.id }),
    };
    let _ = publisher.publish(&event).await;
    Ok(StatusCode::NO_CONTENT)
}
