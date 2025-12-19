use axum::{Json, extract::State};

use crate::context::GitContext;
use crate::http::error::ApiError;
use crate::http::extractors::{WorkspaceAuth, WorkspaceUser};
use application::git::dtos::{GitSyncRequestDto, UpsertGitConfigInput};
use application::domain::access::permissions::PERM_GIT_INIT;

use super::types::{
    CreateGitConfigRequest, GitImportResponse, GitSyncRequest, GitSyncResponse, map_git_error,
};

#[utoipa::path(post, path = "/api/git/sync", tag = "Git", request_body = GitSyncRequest, responses((status = 200, body = GitSyncResponse), (status = 409, description = "Conflicts during rebase/pull")))]
pub async fn sync_now(
    State(ctx): State<GitContext>,
    auth: WorkspaceUser,
    Json(req): Json<GitSyncRequest>,
) -> Result<Json<GitSyncResponse>, ApiError> {
    let service = ctx.git_service();
    let out = service
        .sync_now(
            auth.workspace_id,
            GitSyncRequestDto {
                message: req.message.clone(),
                force: req.force,
                full_scan: req.full_scan,
                skip_push: req.skip_push,
            },
        )
        .await
        .map_err(map_git_error)?;
    Ok(Json(GitSyncResponse {
        success: out.success,
        message: out.message,
        commit_hash: out.commit_hash,
        files_changed: out.files_changed,
    }))
}

#[utoipa::path(
    post,
    path = "/api/git/import",
    tag = "Git",
    request_body = CreateGitConfigRequest,
    responses((status = 200, body = GitImportResponse))
)]
pub async fn import_repository(
    State(ctx): State<GitContext>,
    auth: WorkspaceAuth,
    Json(req): Json<CreateGitConfigRequest>,
) -> Result<Json<GitImportResponse>, ApiError> {
    if req.repository_url.trim().is_empty() {
        return Err(ApiError::bad_request("invalid_repository_url"));
    }
    auth.ensure_permission(PERM_GIT_INIT)?;

    let service = ctx.git_service();
    let dto = service
        .import_repository(
            auth.workspace_id,
            auth.user_id,
            &UpsertGitConfigInput::from(req),
        )
        .await
        .map_err(map_git_error)?;
    Ok(Json(GitImportResponse {
        success: true,
        message: dto.message,
        files_changed: dto.files_changed as i32,
        commit_hash: dto.commit_hash,
        docs_created: dto.docs_created as i32,
        attachments_created: dto.attachments_created as i32,
    }))
}

#[utoipa::path(post, path = "/api/git/init", tag = "Git", responses((status = 200, description = "OK")))]
pub async fn init_repository(
    State(ctx): State<GitContext>,
    auth: WorkspaceUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    let service = ctx.git_service();
    service
        .init_repository(auth.workspace_id)
        .await
        .map_err(map_git_error)?;
    Ok(Json(serde_json::json!({"success":true})))
}

#[utoipa::path(post, path = "/api/git/deinit", tag = "Git", responses((status = 200, description = "OK")))]
pub async fn deinit_repository(
    State(ctx): State<GitContext>,
    auth: WorkspaceUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    let service = ctx.git_service();
    service
        .deinit_repository(auth.workspace_id)
        .await
        .map_err(map_git_error)?;
    Ok(Json(serde_json::json!({"success":true})))
}
