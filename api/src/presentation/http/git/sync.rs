use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};

use crate::application::dto::git::{GitSyncRequestDto, UpsertGitConfigInput};
use crate::domain::workspaces::permissions::PERM_GIT_INIT;
use crate::presentation::context::AppContext;
use crate::presentation::http::auth::{Bearer, validate_bearer};
use crate::presentation::http::workspaces::scope as workspace_scope;

use super::types::{
    CreateGitConfigRequest, GitImportResponse, GitSyncRequest, GitSyncResponse, map_git_error,
};

#[utoipa::path(post, path = "/api/git/sync", tag = "Git", request_body = GitSyncRequest, responses((status = 200, body = GitSyncResponse), (status = 409, description = "Conflicts during rebase/pull")))]
pub async fn sync_now(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Json(req): Json<GitSyncRequest>,
) -> Result<Json<GitSyncResponse>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let service = ctx.git_service();
    let out = service
        .sync_now(
            workspace_id,
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
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Json(req): Json<CreateGitConfigRequest>,
) -> Result<Json<GitImportResponse>, StatusCode> {
    if req.repository_url.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_INIT)
        .await?;

    let service = ctx.git_service();
    let dto = service
        .import_repository(workspace_id, user_id, &UpsertGitConfigInput::from(req))
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
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let service = ctx.git_service();
    service
        .init_repository(workspace_id)
        .await
        .map_err(map_git_error)?;
    Ok(Json(serde_json::json!({"success":true})))
}

#[utoipa::path(post, path = "/api/git/deinit", tag = "Git", responses((status = 200, description = "OK")))]
pub async fn deinit_repository(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let service = ctx.git_service();
    service
        .deinit_repository(workspace_id)
        .await
        .map_err(map_git_error)?;
    Ok(Json(serde_json::json!({"success":true})))
}
