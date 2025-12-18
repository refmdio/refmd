use domain::workspaces::permissions::PERM_PLUGIN_RUN;
use crate::context::AppContext;
use crate::http::identity::auth::Bearer;
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};

use super::types::{KvPath, KvValueBody, KvValueResponse, ensure_valid_plugin_id};
use super::util::{
    PERMISSION_DOC_READ, PERMISSION_DOC_WRITE, map_plugin_service_error,
    resolve_plugin_user_context,
};
use domain::plugins::scope::PluginScope;

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
    let plugin_ctx =
        resolve_plugin_user_context(&ctx, &headers, bearer_token.as_str(), Some(PERM_PLUGIN_RUN))
            .await?;
    let actor = plugin_ctx.actor.clone();
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
        .get_kv(&p.plugin, PluginScope::Doc, Some(p.doc_id), &p.key)
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
    let plugin_ctx =
        resolve_plugin_user_context(&ctx, &headers, bearer_token.as_str(), Some(PERM_PLUGIN_RUN))
            .await?;
    let actor = plugin_ctx.actor.clone();
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
        .put_kv(&p.plugin, PluginScope::Doc, Some(p.doc_id), &p.key, &body.value)
        .await
        .map_err(map_plugin_service_error)?;
    Ok(StatusCode::NO_CONTENT)
}
