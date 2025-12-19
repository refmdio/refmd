use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
};

use crate::context::AppContext;
use crate::http::error::ApiError;
use crate::http::workspaces::scope as workspace_scope;
use crate::security::token::{self, Bearer};
use application::core::services::access;

use super::types::{ApplicableQuery, ApplicableShareItem, map_share_error};

#[utoipa::path(get, path = "/api/shares/applicable", tag = "Sharing",
    params(("doc_id" = Uuid, Query, description = "Document ID")),
    responses((status = 200, description = "Shares that include the document", body = [ApplicableShareItem])))]
pub async fn list_applicable_shares(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Query(q): Query<ApplicableQuery>,
) -> Result<Json<Vec<ApplicableShareItem>>, ApiError> {
    let bearer_token = bearer.0.clone();
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(token::map_actor_error)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let permissions =
        workspace_scope::resolve_workspace_permissions(&ctx, workspace_id, user_id).await?;
    let actor = access::Actor::User(user_id);
    ctx.authorization()
        .require_view(&actor, q.doc_id)
        .await
        .map_err(|err| crate::http::error::map_service_error(err, "authorization_error"))?;

    let service = ctx.share_service();
    let rows = service
        .list_applicable(workspace_id, &permissions, q.doc_id)
        .await
        .map_err(map_share_error)?;
    let items: Vec<ApplicableShareItem> = rows.into_iter().map(Into::into).collect();
    Ok(Json(items))
}
