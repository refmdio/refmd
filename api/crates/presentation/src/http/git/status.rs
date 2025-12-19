use axum::{Json, extract::State, http::HeaderMap};

use crate::context::AppContext;
use crate::http::error::ApiError;
use crate::http::workspaces::scope as workspace_scope;
use crate::security::token::{self, Bearer};
use application::core::dtos::TextDiffResult;
use application::git::dtos::{GitCommitInfo, GitStatusDto};

use super::types::{GitChangesResponse, GitHistoryResponse, GitStatus, map_git_error};

#[utoipa::path(get, path = "/api/git/status", tag = "Git", responses((status = 200, body = GitStatus)))]
pub async fn get_status(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<GitStatus>, ApiError> {
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
    let service = ctx.git_service();
    let dto: GitStatusDto = service
        .get_status(workspace_id)
        .await
        .map_err(map_git_error)?;
    let out: GitStatus = dto.into();
    Ok(Json(out))
}

#[utoipa::path(get, path = "/api/git/changes", tag = "Git", responses((status = 200, body = GitChangesResponse)))]
pub async fn get_changes(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<GitChangesResponse>, ApiError> {
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
    let service = ctx.git_service();
    let files = service
        .get_changes(workspace_id)
        .await
        .map_err(map_git_error)?;
    let items = files.into_iter().map(Into::into).collect();
    Ok(Json(GitChangesResponse { files: items }))
}

#[utoipa::path(get, path = "/api/git/history", tag = "Git", responses((status = 200, body = GitHistoryResponse)))]
pub async fn get_history(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<GitHistoryResponse>, ApiError> {
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
    let service = ctx.git_service();
    let commits: Vec<GitCommitInfo> = service
        .get_history(workspace_id)
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
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<Vec<TextDiffResult>>, ApiError> {
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
    let service = ctx.git_service();
    let diffs = service
        .get_working_diff(workspace_id)
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
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    axum::extract::Path((from, to)): axum::extract::Path<(String, String)>,
) -> Result<Json<Vec<TextDiffResult>>, ApiError> {
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
    let service = ctx.git_service();
    let diffs = service
        .get_commit_diff(workspace_id, &from, &to)
        .await
        .map_err(map_git_error)?;
    Ok(Json(diffs))
}
