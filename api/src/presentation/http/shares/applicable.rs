use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
};
use uuid::Uuid;

use crate::application::access;
use crate::presentation::context::AppContext;
use crate::presentation::http::auth::Bearer;
use crate::presentation::http::workspaces::scope as workspace_scope;

use super::types::{ApplicableQuery, ApplicableShareItem, map_share_error};

#[utoipa::path(get, path = "/api/shares/applicable", tag = "Sharing",
    params(("doc_id" = Uuid, Query, description = "Document ID")),
    responses((status = 200, description = "Shares that include the document", body = [ApplicableShareItem])))]
pub async fn list_applicable_shares(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Query(q): Query<ApplicableQuery>,
) -> Result<Json<Vec<ApplicableShareItem>>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
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
        .map_err(|_| StatusCode::FORBIDDEN)?;

    let service = ctx.share_service();
    let rows = service
        .list_applicable(workspace_id, &permissions, q.doc_id)
        .await
        .map_err(map_share_error)?;
    let items: Vec<ApplicableShareItem> = rows.into_iter().map(Into::into).collect();
    Ok(Json(items))
}
