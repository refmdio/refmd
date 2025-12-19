use axum::{Json, extract::State};

use crate::context::GitContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceUser;
use application::git::dtos::{GitCommitInfo, GitStatusDto};
use contracts::core::dtos::TextDiffResult;

use super::types::{GitChangesResponse, GitHistoryResponse, GitStatus, map_git_error};

#[utoipa::path(get, path = "/api/git/status", tag = "Git", responses((status = 200, body = GitStatus)))]
pub async fn get_status(
    State(ctx): State<GitContext>,
    auth: WorkspaceUser,
) -> Result<Json<GitStatus>, ApiError> {
    let service = ctx.git_service();
    let dto: GitStatusDto = service
        .get_status(auth.workspace_id)
        .await
        .map_err(map_git_error)?;
    let out: GitStatus = dto.into();
    Ok(Json(out))
}

#[utoipa::path(get, path = "/api/git/changes", tag = "Git", responses((status = 200, body = GitChangesResponse)))]
pub async fn get_changes(
    State(ctx): State<GitContext>,
    auth: WorkspaceUser,
) -> Result<Json<GitChangesResponse>, ApiError> {
    let service = ctx.git_service();
    let files = service
        .get_changes(auth.workspace_id)
        .await
        .map_err(map_git_error)?;
    let items = files.into_iter().map(Into::into).collect();
    Ok(Json(GitChangesResponse { files: items }))
}

#[utoipa::path(get, path = "/api/git/history", tag = "Git", responses((status = 200, body = GitHistoryResponse)))]
pub async fn get_history(
    State(ctx): State<GitContext>,
    auth: WorkspaceUser,
) -> Result<Json<GitHistoryResponse>, ApiError> {
    let service = ctx.git_service();
    let commits: Vec<GitCommitInfo> = service
        .get_history(auth.workspace_id)
        .await
        .map_err(map_git_error)?;
    let out = commits.into_iter().map(Into::into).collect();
    Ok(Json(GitHistoryResponse { commits: out }))
}

#[utoipa::path(
    get,
    path = "/api/git/diff/working",
    tag = "Git",
    responses((status = 200, body = [TextDiffResult]))
)]
pub async fn get_working_diff(
    State(ctx): State<GitContext>,
    auth: WorkspaceUser,
) -> Result<Json<Vec<TextDiffResult>>, ApiError> {
    let service = ctx.git_service();
    let diffs = service
        .get_working_diff(auth.workspace_id)
        .await
        .map_err(map_git_error)?;
    Ok(Json(diffs))
}

#[utoipa::path(
    get,
    path = "/api/git/diff/commits/{from}/{to}",
    params(("from" = String, Path, description = "From"), ("to" = String, Path, description = "To")),
    tag = "Git",
    responses((status = 200, body = [TextDiffResult]))
)]
pub async fn get_commit_diff(
    State(ctx): State<GitContext>,
    auth: WorkspaceUser,
    axum::extract::Path((from, to)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<TextDiffResult>>, ApiError> {
    let service = ctx.git_service();
    let diffs = service
        .get_commit_diff(auth.workspace_id, &from, &to)
        .await
        .map_err(map_git_error)?;
    Ok(Json(diffs))
}
