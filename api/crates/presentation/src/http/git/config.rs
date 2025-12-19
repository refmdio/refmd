use axum::{Json, extract::State, http::StatusCode};

use crate::context::GitContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
use application::core::services::errors::ServiceError;
use application::git::dtos::GitConfigDto;
use application::git::dtos::UpsertGitConfigInput;
use domain::access::permissions::{PERM_GIT_CONFIGURE, PERM_GIT_INIT, PERM_GIT_SYNC};

use super::types::{
    CreateGitConfigRequest, GitConfigResponse, GitRemoteCheckResponse, map_git_error,
};

#[utoipa::path(get, path = "/api/git/config", tag = "Git", responses((status = 200, body = Option<GitConfigResponse>)))]
pub async fn get_config(
    State(ctx): State<GitContext>,
    auth: WorkspaceAuth,
) -> Result<Json<Option<GitConfigResponse>>, ApiError> {
    auth.ensure_permission(PERM_GIT_INIT)?;
    auth.ensure_permission(PERM_GIT_SYNC)?;
    auth.ensure_permission(PERM_GIT_CONFIGURE)?;
    let service = ctx.git_service();
    let resp: Option<GitConfigDto> = service
        .get_config(auth.workspace_id)
        .await
        .map_err(map_git_error)?;
    let mut out: Option<GitConfigResponse> = resp.map(Into::into);
    if let Some(ref mut cfg) = out
        && let Some(check) = service
            .check_remote(auth.workspace_id)
            .await
            .map_err(map_git_error)?
    {
        cfg.remote_check = Some(GitRemoteCheckResponse::from(check));
    }
    Ok(Json(out))
}

#[utoipa::path(post, path = "/api/git/config", tag = "Git", request_body = CreateGitConfigRequest, responses((status = 200, body = GitConfigResponse)))]
pub async fn create_or_update_config(
    State(ctx): State<GitContext>,
    auth: WorkspaceAuth,
    Json(req): Json<CreateGitConfigRequest>,
) -> Result<Json<GitConfigResponse>, ApiError> {
    auth.ensure_permission(PERM_GIT_INIT)?;
    auth.ensure_permission(PERM_GIT_SYNC)?;
    auth.ensure_permission(PERM_GIT_CONFIGURE)?;
    let input: UpsertGitConfigInput = req.into();
    let service = ctx.git_service();
    let resp: GitConfigDto = service
        .upsert_config(auth.workspace_id, &input)
        .await
        .map_err(|err| match err {
            ServiceError::BadRequest(code) => ApiError::bad_request(code).with_message(code),
            other => map_git_error(other),
        })?;
    let mut out: GitConfigResponse = resp.into();
    if let Some(check) = service
        .check_remote(auth.workspace_id)
        .await
        .map_err(map_git_error)?
    {
        out.remote_check = Some(check.into());
    }
    Ok(Json(out))
}

#[utoipa::path(delete, path = "/api/git/config", tag = "Git", responses((status = 204, description = "Deleted")))]
pub async fn delete_config(
    State(ctx): State<GitContext>,
    auth: WorkspaceAuth,
) -> Result<StatusCode, ApiError> {
    auth.ensure_permission(PERM_GIT_SYNC)?;
    auth.ensure_permission(PERM_GIT_CONFIGURE)?;
    let service = ctx.git_service();
    service
        .delete_config(auth.workspace_id)
        .await
        .map_err(map_git_error)?;
    Ok(StatusCode::NO_CONTENT)
}
