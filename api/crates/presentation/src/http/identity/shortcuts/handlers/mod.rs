use axum::{Json, extract::State};

use crate::context::IdentityContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
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
    auth: WorkspaceAuth,
) -> Result<Json<UserShortcutResponse>, ApiError> {
    let service = ctx.user_shortcut_service();
    let profile = service
        .get_profile(auth.workspace_id, auth.user_id, &auth.permissions)
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
    auth: WorkspaceAuth,
    Json(payload): Json<UpdateUserShortcutRequest>,
) -> Result<Json<UserShortcutResponse>, ApiError> {
    let service = ctx.user_shortcut_service();
    let result = service
        .update_profile(
            auth.workspace_id,
            auth.user_id,
            &auth.permissions,
            payload.bindings,
            payload.leader_key,
        )
        .await
        .map_err(map_shortcut_error)?;
    Ok(Json(UserShortcutResponse::from(result)))
}
