use axum::{
    Json,
    extract::State,
    http::HeaderMap,
};

use crate::context::AppContext;
use crate::http::error::ApiError;
use crate::http::workspaces::scope as workspace_scope;
use crate::security::token::{self, Bearer};

use super::types::{ActiveShareItem, frontend_base, map_share_error};
use application::documents::dtos::ActiveShareItemDto;

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
) -> Result<Json<Vec<ActiveShareItem>>, ApiError> {
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
