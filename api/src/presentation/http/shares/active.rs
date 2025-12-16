use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};

use crate::presentation::context::AppContext;
use crate::presentation::http::auth::Bearer;
use crate::presentation::http::workspaces::scope as workspace_scope;

use super::types::{ActiveShareItem, frontend_base, map_share_error};
use crate::application::dto::shares::ActiveShareItemDto;

#[utoipa::path(
    get,
    path = "/api/shares/active",
    tag = "Sharing",
    responses((status = 200, description = "Active shares", body = [ActiveShareItem]))
)]
pub async fn list_active_shares(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<Vec<ActiveShareItem>>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let permissions =
        workspace_scope::resolve_workspace_permissions(&ctx, workspace_id, user_id).await?;
    let service = ctx.share_service();
    let items: Vec<ActiveShareItemDto> = service
        .list_active(workspace_id, &permissions)
        .await
        .map_err(map_share_error)?;
    let base = frontend_base(&ctx.cfg);
    let out: Vec<ActiveShareItem> = items
        .into_iter()
        .map(|dto| ActiveShareItem::from((dto, base.clone())))
        .collect();
    Ok(Json(out))
}
