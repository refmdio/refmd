use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use uuid::Uuid;

use crate::application::services::errors::ServiceError;
use crate::presentation::context::AppContext;
use crate::presentation::http::auth::{self, Bearer};
use crate::presentation::http::workspaces::scope as workspace_scope;
use tracing::error;

use super::types::{UpdateUserShortcutRequest, UserShortcutResponse};

fn map_shortcut_error(err: ServiceError) -> StatusCode {
    match err {
        ServiceError::Unauthorized | ServiceError::TokenExpired => StatusCode::UNAUTHORIZED,
        ServiceError::Forbidden => StatusCode::FORBIDDEN,
        ServiceError::Conflict => StatusCode::CONFLICT,
        ServiceError::NotFound => StatusCode::NOT_FOUND,
        ServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
        ServiceError::Unexpected(inner) => {
            error!(error = ?inner, "user_shortcut_service_error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/me/shortcuts",
    tag = "Auth",
    responses((status = 200, body = UserShortcutResponse))
)]
pub async fn get_user_shortcuts(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<UserShortcutResponse>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = auth::validate_bearer(&ctx, Bearer(bearer_token.clone())).await?;
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
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Json(payload): Json<UpdateUserShortcutRequest>,
) -> Result<Json<UserShortcutResponse>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = auth::validate_bearer(&ctx, Bearer(bearer_token.clone())).await?;
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
