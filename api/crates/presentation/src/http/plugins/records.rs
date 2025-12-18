use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
};
use serde_json::json;
use std::collections::HashMap;

use crate::context::AppContext;
use crate::http::identity::auth::Bearer;
use domain::access::permissions::PERM_PLUGIN_RUN;

use super::types::{
    CreateRecordBody, RecordsPath, RecordsResponse, UpdateRecordBody, UpdateRecordPath,
    ensure_valid_plugin_id,
};
use super::util::{
    PERMISSION_DOC_READ, PERMISSION_DOC_WRITE, map_plugin_service_error,
    resolve_plugin_user_context,
};
use domain::plugins::scope::PluginRecordScope;

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
    let plugin_ctx =
        resolve_plugin_user_context(&ctx, &headers, bearer_token.as_str(), Some(PERM_PLUGIN_RUN))
            .await?;
    let actor = plugin_ctx.actor;
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
        .list_records(
            &p.plugin,
            PluginRecordScope::Doc,
            p.doc_id,
            &p.kind,
            limit,
            offset,
        )
        .await
        .map_err(map_plugin_service_error)?;
    let mut items = Vec::with_capacity(rows.len());
    for r in rows {
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

    let mut data = body.data;
    data["authorId"] = json!(plugin_ctx.user_id);

    let plugin_data = ctx.plugin_data_service();
    let rec = plugin_data
        .create_record(&p.plugin, PluginRecordScope::Doc, p.doc_id, &p.kind, &data)
        .await
        .map_err(map_plugin_service_error)?;
    Ok(Json(json!({
        "id": rec.id,
        "data": rec.data,
        "createdAt": rec.created_at,
        "updatedAt": rec.updated_at,
    })))
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
    let plugin_ctx = resolve_plugin_user_context(
        &ctx,
        &headers,
        bearer_token_raw.as_str(),
        Some(PERM_PLUGIN_RUN),
    )
    .await?;
    let actor = plugin_ctx.actor.clone();

    let plugin_data = ctx.plugin_data_service();
    let rec = plugin_data
        .get_record(p.id)
        .await
        .map_err(map_plugin_service_error)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if rec.plugin != p.plugin {
        return Err(StatusCode::NOT_FOUND);
    }
    if rec.scope != PluginRecordScope::Doc {
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
    let plugin_ctx = resolve_plugin_user_context(
        &ctx,
        &headers,
        bearer_token_raw.as_str(),
        Some(PERM_PLUGIN_RUN),
    )
    .await?;
    let actor = plugin_ctx.actor.clone();
    let plugin_data = ctx.plugin_data_service();
    let rec = plugin_data
        .get_record(p.id)
        .await
        .map_err(map_plugin_service_error)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if rec.plugin != p.plugin {
        return Err(StatusCode::NOT_FOUND);
    }
    if rec.scope != PluginRecordScope::Doc {
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
