use axum::response::sse::{Event, KeepAlive, Sse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
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
use crate::application::services::errors::ServiceError;
use crate::application::services::plugins::management::{
    self, AssetRequestScope, PluginAssetRequest, PluginManifestItem,
};
use crate::application::use_cases::plugins::install_from_url::InstallPluginError;
use crate::domain::workspaces::permissions::{
    PERM_PLUGIN_INSTALL, PERM_PLUGIN_RUN, PERM_PLUGIN_UNINSTALL, PermissionSet,
};
use crate::presentation::context::AppContext;
use crate::presentation::http::auth::{self, Bearer};
use crate::presentation::http::workspace_scope;

const PERMISSION_DOC_READ: &str = "doc.read";
const PERMISSION_DOC_WRITE: &str = "doc.write";

struct PluginUserContext {
    workspace_id: Uuid,
    user_id: Uuid,
    permissions: PermissionSet,
}

async fn resolve_plugin_user_context(
    ctx: &AppContext,
    headers: &HeaderMap,
    bearer_token: &str,
    user_id: Uuid,
    required_permission: Option<&str>,
) -> Result<PluginUserContext, StatusCode> {
    let workspace_id =
        workspace_scope::resolve_active_workspace_id(ctx, headers, Some(bearer_token), user_id)
            .await
            .map_err(|_| StatusCode::FORBIDDEN)?;
    let permissions = workspace_scope::resolve_workspace_permissions(ctx, workspace_id, user_id)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    if let Some(permission) = required_permission {
        if !permissions.allows(permission) {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    Ok(PluginUserContext {
        workspace_id,
        user_id,
        permissions,
    })
}

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
        .route("/plugin-assets", get(get_plugin_asset))
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

impl From<PluginManifestItem> for ManifestItem {
    fn from(value: PluginManifestItem) -> Self {
        Self {
            id: value.id,
            name: value.name,
            version: value.version,
            scope: value.scope,
            mounts: value.mounts,
            frontend: value.frontend,
            permissions: value.permissions,
            config: value.config,
            ui: value.ui,
            author: value.author,
            repository: value.repository,
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
        ("offset" = Option<i64>, Query, description = "Offset")
    ),
    responses((status = 200, body = RecordsResponse)),
    tag = "Plugins"
)]
pub async fn list_records(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    Path(p): Path<RecordsPath>,
) -> Result<Json<RecordsResponse>, StatusCode> {
    ensure_valid_plugin_id(&p.plugin)?;
    let bearer_token = bearer.0;
    let sub = auth::validate_bearer_public(&ctx, Bearer(bearer_token.clone())).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let plugin_ctx = resolve_plugin_user_context(
        &ctx,
        &headers,
        bearer_token.as_str(),
        user_id,
        Some(PERM_PLUGIN_RUN),
    )
    .await?;
    let actor = access::Actor::User(plugin_ctx.user_id);
    ctx.authorization()
        .require_view(&actor, p.doc_id)
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

    ctx.plugin_permissions()
        .ensure(
            Some(plugin_ctx.workspace_id),
            &p.plugin,
            PERMISSION_DOC_READ,
        )
        .await
        .map_err(map_plugin_service_error)?;

    let plugin_data = ctx.plugin_data_service();
    let rows = plugin_data
        .list_records(&p.plugin, "doc", p.doc_id, &p.kind, limit, offset)
        .await
        .map_err(map_plugin_service_error)?;
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
        ("kind" = String, Path, description = "Record kind")
    ),
    responses((status = 200, body = serde_json::Value)),
    tag = "Plugins",
    operation_id = "pluginsCreateRecord"
)]
pub async fn create_record(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Path(p): Path<RecordsPath>,
    Json(body): Json<CreateRecordBody>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    ensure_valid_plugin_id(&p.plugin)?;
    let bearer_token = bearer.0;
    let sub = auth::validate_bearer_public(&ctx, Bearer(bearer_token.clone())).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let plugin_ctx = resolve_plugin_user_context(
        &ctx,
        &headers,
        bearer_token.as_str(),
        user_id,
        Some(PERM_PLUGIN_RUN),
    )
    .await?;
    let actor = access::Actor::User(plugin_ctx.user_id);
    ctx.authorization()
        .require_edit(&actor, p.doc_id)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;

    ctx.plugin_permissions()
        .ensure(
            Some(plugin_ctx.workspace_id),
            &p.plugin,
            PERMISSION_DOC_WRITE,
        )
        .await
        .map_err(map_plugin_service_error)?;

    // Attach authorId and timestamps if not provided
    let mut data = body.data;
    data["authorId"] = json!(plugin_ctx.user_id);

    let plugin_data = ctx.plugin_data_service();
    let rec = plugin_data
        .create_record(&p.plugin, "doc", p.doc_id, &p.kind, &data)
        .await
        .map_err(map_plugin_service_error)?;
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
    headers: HeaderMap,
    Path(p): Path<UpdateRecordPath>,
    Json(body): Json<UpdateRecordBody>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    ensure_valid_plugin_id(&p.plugin)?;
    let bearer_token_raw = bearer.0;
    let sub = crate::presentation::http::auth::validate_bearer_public(
        &ctx,
        Bearer(bearer_token_raw.clone()),
    )
    .await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let plugin_ctx = resolve_plugin_user_context(
        &ctx,
        &headers,
        bearer_token_raw.as_str(),
        user_id,
        Some(PERM_PLUGIN_RUN),
    )
    .await?;
    let actor = access::Actor::User(plugin_ctx.user_id);

    let plugin_data = ctx.plugin_data_service();
    // Get record for scope info and docId to enforce edit permission
    let rec = plugin_data
        .get_record(p.id)
        .await
        .map_err(map_plugin_service_error)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if rec.plugin != p.plugin {
        return Err(StatusCode::NOT_FOUND);
    }

    // Edit permission on the doc scope
    ctx.authorization()
        .require_edit(&actor, rec.scope_id)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;

    ctx.plugin_permissions()
        .ensure(
            Some(plugin_ctx.workspace_id),
            &p.plugin,
            PERMISSION_DOC_WRITE,
        )
        .await
        .map_err(map_plugin_service_error)?;

    let updated = plugin_data
        .update_record(p.id, &body.patch)
        .await
        .map_err(map_plugin_service_error)?
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
    headers: HeaderMap,
    Path(p): Path<UpdateRecordPath>,
) -> Result<StatusCode, StatusCode> {
    ensure_valid_plugin_id(&p.plugin)?;
    let bearer_token_raw = bearer.0;
    let sub = crate::presentation::http::auth::validate_bearer_public(
        &ctx,
        Bearer(bearer_token_raw.clone()),
    )
    .await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let plugin_ctx = resolve_plugin_user_context(
        &ctx,
        &headers,
        bearer_token_raw.as_str(),
        user_id,
        Some(PERM_PLUGIN_RUN),
    )
    .await?;
    let actor = access::Actor::User(plugin_ctx.user_id);
    let plugin_data = ctx.plugin_data_service();
    // Get record to authorize
    let rec = plugin_data
        .get_record(p.id)
        .await
        .map_err(map_plugin_service_error)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if rec.plugin != p.plugin {
        return Err(StatusCode::NOT_FOUND);
    }

    ctx.authorization()
        .require_edit(&actor, rec.scope_id)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;

    ctx.plugin_permissions()
        .ensure(
            Some(plugin_ctx.workspace_id),
            &p.plugin,
            PERMISSION_DOC_WRITE,
        )
        .await
        .map_err(map_plugin_service_error)?;

    let ok = plugin_data
        .delete_record(p.id)
        .await
        .map_err(map_plugin_service_error)?;
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
    params(("plugin" = String, Path, description = "Plugin ID"), ("doc_id" = Uuid, Path, description = "Document ID"), ("key" = String, Path, description = "Key")),
    responses((status = 200, body = KvValueResponse)),
    tag = "Plugins",
    operation_id = "pluginsGetKv"
)]
pub async fn get_kv_value(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Path(p): Path<KvPath>,
) -> Result<Json<KvValueResponse>, StatusCode> {
    ensure_valid_plugin_id(&p.plugin)?;
    let bearer_token = bearer.0;
    let sub = auth::validate_bearer_public(&ctx, Bearer(bearer_token.clone())).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let plugin_ctx = resolve_plugin_user_context(
        &ctx,
        &headers,
        bearer_token.as_str(),
        user_id,
        Some(PERM_PLUGIN_RUN),
    )
    .await?;
    let actor = access::Actor::User(plugin_ctx.user_id);
    ctx.authorization()
        .require_view(&actor, p.doc_id)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;

    ctx.plugin_permissions()
        .ensure(
            Some(plugin_ctx.workspace_id),
            &p.plugin,
            PERMISSION_DOC_READ,
        )
        .await
        .map_err(map_plugin_service_error)?;

    let plugin_data = ctx.plugin_data_service();
    let val = plugin_data
        .get_kv(&p.plugin, "doc", Some(p.doc_id), &p.key)
        .await
        .map_err(map_plugin_service_error)?
        .unwrap_or(serde_json::Value::Null);
    Ok(Json(KvValueResponse { value: val }))
}

#[utoipa::path(
    put,
    path = "/api/plugins/{plugin}/docs/{doc_id}/kv/{key}",
    request_body = KvValueBody,
    params(("plugin" = String, Path, description = "Plugin ID"), ("doc_id" = Uuid, Path, description = "Document ID"), ("key" = String, Path, description = "Key")),
    responses((status = 204)),
    tag = "Plugins",
    operation_id = "pluginsPutKv"
)]
pub async fn put_kv_value(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Path(p): Path<KvPath>,
    Json(body): Json<KvValueBody>,
) -> Result<StatusCode, StatusCode> {
    ensure_valid_plugin_id(&p.plugin)?;
    let bearer_token = bearer.0;
    let sub = auth::validate_bearer_public(&ctx, Bearer(bearer_token.clone())).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let plugin_ctx = resolve_plugin_user_context(
        &ctx,
        &headers,
        bearer_token.as_str(),
        user_id,
        Some(PERM_PLUGIN_RUN),
    )
    .await?;
    let actor = access::Actor::User(plugin_ctx.user_id);
    ctx.authorization()
        .require_edit(&actor, p.doc_id)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;

    ctx.plugin_permissions()
        .ensure(
            Some(plugin_ctx.workspace_id),
            &p.plugin,
            PERMISSION_DOC_WRITE,
        )
        .await
        .map_err(map_plugin_service_error)?;

    let plugin_data = ctx.plugin_data_service();
    plugin_data
        .put_kv(&p.plugin, "doc", Some(p.doc_id), &p.key, &body.value)
        .await
        .map_err(map_plugin_service_error)?;
    Ok(StatusCode::NO_CONTENT)
}

fn ensure_valid_plugin_id(id: &str) -> Result<(), StatusCode> {
    management::validate_plugin_id(id).map_err(map_plugin_service_error)
}

fn map_plugin_service_error(err: ServiceError) -> StatusCode {
    match err {
        ServiceError::Unauthorized | ServiceError::TokenExpired => StatusCode::UNAUTHORIZED,
        ServiceError::Forbidden => StatusCode::FORBIDDEN,
        ServiceError::Conflict => StatusCode::CONFLICT,
        ServiceError::NotFound => StatusCode::NOT_FOUND,
        ServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
        ServiceError::Unexpected(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn extract_doc_id(value: &serde_json::Value) -> Option<Uuid> {
    value
        .get("docId")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .or_else(|| {
            value
                .get("payload")
                .and_then(|payload| payload.get("docId"))
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok())
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
    headers: HeaderMap,
) -> Result<Json<Vec<ManifestItem>>, StatusCode> {
    let bearer_token = bearer.0;
    let sub = auth::validate_bearer_public(&ctx, Bearer(bearer_token.clone())).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let plugin_ctx =
        resolve_plugin_user_context(&ctx, &headers, bearer_token.as_str(), user_id, None).await?;
    let manifests = ctx
        .plugin_management()
        .manifests_for_workspace(plugin_ctx.workspace_id, plugin_ctx.user_id)
        .await
        .map_err(map_plugin_service_error)?
        .into_iter()
        .map(ManifestItem::from)
        .collect();
    Ok(Json(manifests))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ExecBody {
    payload: Option<serde_json::Value>,
}

#[utoipa::path(
    post,
    path = "/api/plugins/{plugin}/exec/{action}",
    request_body = ExecBody,
    params(
        ("plugin" = String, Path, description = "Plugin ID"),
        ("action" = String, Path, description = "Action")
    ),
    responses((status = 200, body = ExecResultResponse)),
    tag = "Plugins",
    operation_id = "pluginsExecAction"
)]
pub async fn exec_action(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Path((plugin, action)): Path<(String, String)>,
    Json(body): Json<ExecBody>,
) -> Result<Json<ExecResultResponse>, StatusCode> {
    ensure_valid_plugin_id(&plugin)?;
    let bearer_token = bearer.0;
    let sub = auth::validate_bearer_public(&ctx, Bearer(bearer_token.clone())).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let plugin_ctx = resolve_plugin_user_context(
        &ctx,
        &headers,
        bearer_token.as_str(),
        user_id,
        Some(PERM_PLUGIN_RUN),
    )
    .await?;
    let actor = access::Actor::User(plugin_ctx.user_id);
    if let Some(payload) = body.payload.as_ref() {
        if let Some(doc_id) = extract_doc_id(payload) {
            ctx.authorization()
                .require_edit(&actor, doc_id)
                .await
                .map_err(|_| StatusCode::FORBIDDEN)?;
        }
    }
    let exec_service = ctx.plugin_execution_service();
    match exec_service
        .execute_action(
            plugin_ctx.workspace_id,
            plugin_ctx.user_id,
            &plugin_ctx.permissions,
            &plugin,
            &action,
            body.payload.clone(),
        )
        .await
        .map_err(map_plugin_service_error)?
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
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let initial = stream::iter(vec![Ok(Event::default().event("ready").data("{}\n"))]);
    let event_stream = ctx
        .subscribe_plugin_events()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let broadcast = event_stream.filter_map(move |ev| {
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
    headers: HeaderMap,
    Json(body): Json<InstallFromUrlBody>,
) -> Result<Json<InstallResponse>, StatusCode> {
    let bearer_token_raw = bearer.0;
    let sub = crate::presentation::http::auth::validate_bearer_public(
        &ctx,
        Bearer(bearer_token_raw.clone()),
    )
    .await?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let plugin_ctx = resolve_plugin_user_context(
        &ctx,
        &headers,
        bearer_token_raw.as_str(),
        user_id,
        Some(PERM_PLUGIN_INSTALL),
    )
    .await?;

    let management = ctx.plugin_management();

    match management
        .install_from_url(
            plugin_ctx.workspace_id,
            plugin_ctx.user_id,
            &plugin_ctx.permissions,
            &body.url,
            body.token.as_deref(),
        )
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
    headers: HeaderMap,
    Json(body): Json<UninstallBody>,
) -> Result<StatusCode, StatusCode> {
    let bearer_token_raw = bearer.0;
    let sub = crate::presentation::http::auth::validate_bearer_public(
        &ctx,
        Bearer(bearer_token_raw.clone()),
    )
    .await?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let plugin_ctx = resolve_plugin_user_context(
        &ctx,
        &headers,
        bearer_token_raw.as_str(),
        user_id,
        Some(PERM_PLUGIN_UNINSTALL),
    )
    .await?;
    let UninstallBody { id } = body;
    let trimmed_id = id.trim();
    ensure_valid_plugin_id(trimmed_id)?;
    ctx.plugin_management()
        .uninstall(
            plugin_ctx.workspace_id,
            plugin_ctx.user_id,
            &plugin_ctx.permissions,
            trimmed_id,
        )
        .await
        .map_err(map_plugin_service_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/plugin-assets",
    params(("token" = Option<String>, Query, description = "Share token (optional)")),
    responses((status = 200, description = "Plugin asset")),
    tag = "Plugins",
    operation_id = "pluginsGetAsset"
)]
pub async fn get_plugin_asset(
    State(ctx): State<AppContext>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, StatusCode> {
    let scope_raw = params
        .get("scope")
        .map(|s| s.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let plugin_id = params
        .get("plugin")
        .map(|s| s.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let version = params
        .get("version")
        .map(|s| s.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let path = params
        .get("path")
        .map(|s| s.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let exp = params
        .get("exp")
        .map(|s| s.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let expires_at = exp.parse::<i64>().map_err(|_| StatusCode::BAD_REQUEST)?;
    let sig = params
        .get("sig")
        .map(|s| s.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let share_owned = params
        .get("share")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let scope = match scope_raw {
        "global" => AssetRequestScope::Global,
        "user" => {
            let owner_str = params
                .get("owner")
                .map(|s| s.as_str())
                .ok_or(StatusCode::BAD_REQUEST)?;
            let owner_id = Uuid::parse_str(owner_str).map_err(|_| StatusCode::BAD_REQUEST)?;
            AssetRequestScope::User {
                owner_id,
                share_token: share_owned.as_deref(),
            }
        }
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let payload = ctx
        .plugin_management()
        .fetch_asset(PluginAssetRequest {
            scope,
            plugin_id,
            version,
            path,
            expires_at,
            signature: sig,
        })
        .await
        .map_err(map_plugin_service_error)?;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&payload.content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=60"),
    );
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );

    Ok((headers, payload.bytes).into_response())
}
