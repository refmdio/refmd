use axum::{Json, extract::State, http::HeaderMap};

use crate::context::IdentityContext;
use crate::http::error::ApiError;
use crate::http::identity::auth::Bearer;
use crate::http::workspaces::scope as workspace_scope;
use crate::security::token;
use application::core::services::errors::ServiceError;

use super::types::{UpdateUserShortcutRequest, UserShortcutResponse};

fn map_shortcut_error(err: ServiceError) -> crate::http::error::ApiError {
    crate::http::error::map_service_error(err, "user_shortcut_service_error")
}

#[utoipa::path(
    get,
    path = "/api/me/shortcuts",
    tag = "Auth",
    responses((status = 200, body = UserShortcutResponse))
)]
pub async fn get_user_shortcuts(
    State(ctx): State<IdentityContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<UserShortcutResponse>, ApiError> {
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
    let service = ctx.user_shortcut_service();
    let profile = service
        .get_profile(workspace_id, user_id, &permissions)
        .await
        .map_err(map_shortcut_error)?;
    let response = profile
        .map(UserShortcutResponse::from)
        .unwrap_or_else(UserShortcutResponse::empty);
    Ok(Json(response))
}

#[utoipa::path(
    put,
    path = "/api/me/shortcuts",
    tag = "Auth",
    request_body = UpdateUserShortcutRequest,
    responses((status = 200, body = UserShortcutResponse))
)]
pub async fn update_user_shortcuts(
    State(ctx): State<IdentityContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Json(payload): Json<UpdateUserShortcutRequest>,
) -> Result<Json<UserShortcutResponse>, ApiError> {
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
    let service = ctx.user_shortcut_service();
    let result = service
        .update_profile(
            workspace_id,
            user_id,
            &permissions,
            payload.bindings,
            payload.leader_key,
        )
        .await
        .map_err(map_shortcut_error)?;
    Ok(Json(UserShortcutResponse::from(result)))
}
