use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde_json::json;

use application::core::services::access;
use domain::documents::doc_type::DocumentType;
use domain::workspaces::permissions::PERM_PLUGIN_RUN;
use crate::context::AppContext;
use crate::http::identity::auth::Bearer;

use super::types::{ExecBody, ExecResultResponse, ensure_valid_plugin_id, extract_doc_id};
use super::util::{map_plugin_service_error, resolve_plugin_user_context};

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
    let plugin_ctx =
        resolve_plugin_user_context(&ctx, &headers, bearer_token.as_str(), Some(PERM_PLUGIN_RUN))
            .await?;
    let actor = plugin_ctx.actor.clone();
    let doc_id_from_payload = body.payload.as_ref().and_then(extract_doc_id);
    let doc_id_from_share = if doc_id_from_payload.is_none() {
        if let access::Actor::ShareToken(token) = &actor {
            ctx.share_service()
                .resolve_share_context(token)
                .await
                .map_err(map_plugin_service_error)?
                .and_then(|ctx| {
                    if ctx.shared_type == DocumentType::Document {
                        Some(ctx.shared_id)
                    } else {
                        None
                    }
                })
        } else {
            None
        }
    } else {
        None
    };
    let effective_doc_id = doc_id_from_payload.or(doc_id_from_share);
    if let Some(doc_id) = effective_doc_id {
        let auth = ctx.authorization();
        if let access::Actor::ShareToken(_) = &actor {
            auth.require_view(&actor, doc_id)
                .await
                .map_err(|_| StatusCode::FORBIDDEN)?;
        } else {
            auth.require_edit(&actor, doc_id)
                .await
                .map_err(|_| StatusCode::FORBIDDEN)?;
        }
    }
    let allowed_doc_id = match &actor {
        access::Actor::ShareToken(_) => effective_doc_id,
        _ => None,
    };
    let exec_service = ctx.plugin_execution_service();
    match exec_service
        .execute_action(
            plugin_ctx.workspace_id,
            plugin_ctx.user_id,
            &plugin_ctx.permissions,
            &plugin,
            &action,
            body.payload.clone(),
            allowed_doc_id,
            &actor,
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
