use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};

use crate::application::dto::git::GitConfigDto;
use crate::application::dto::git::UpsertGitConfigInput;
use crate::application::services::errors::ServiceError;
use crate::domain::workspaces::permissions::{PERM_GIT_CONFIGURE, PERM_GIT_INIT, PERM_GIT_SYNC};
use crate::presentation::context::AppContext;
use crate::presentation::http::auth::{Bearer, validate_bearer};
use crate::presentation::http::workspaces::scope as workspace_scope;

use super::types::{
    CreateGitConfigRequest, GitConfigResponse, GitRemoteCheckResponse, map_git_error,
};

#[utoipa::path(get, path = "/api/git/config", tag = "Git", responses((status = 200, body = Option<GitConfigResponse>)))]
pub async fn get_config(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<Option<GitConfigResponse>>, StatusCode> {
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
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_SYNC)
        .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_CONFIGURE)
        .await?;
    let service = ctx.git_service();
    let resp: Option<GitConfigDto> = service
        .get_config(workspace_id)
        .await
        .map_err(map_git_error)?;
    let mut out: Option<GitConfigResponse> = resp.map(Into::into);
    if let Some(ref mut cfg) = out {
        if let Some(check) = service
            .check_remote(workspace_id)
            .await
            .map_err(map_git_error)?
        {
            cfg.remote_check = Some(GitRemoteCheckResponse::from(check));
        }
    }
    Ok(Json(out))
}

#[utoipa::path(post, path = "/api/git/config", tag = "Git", request_body = CreateGitConfigRequest, responses((status = 200, body = GitConfigResponse)))]
pub async fn create_or_update_config(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Json(req): Json<CreateGitConfigRequest>,
) -> Result<Json<GitConfigResponse>, StatusCode> {
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
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_SYNC)
        .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_CONFIGURE)
        .await?;
    let input: UpsertGitConfigInput = req.into();
    let service = ctx.git_service();
    let resp: GitConfigDto = service
        .upsert_config(workspace_id, &input)
        .await
        .map_err(|err| match err {
            ServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
            other => map_git_error(other),
        })?;
    let mut out: GitConfigResponse = resp.into();
    if let Some(check) = service
        .check_remote(workspace_id)
        .await
        .map_err(map_git_error)?
    {
        out.remote_check = Some(check.into());
    }
    Ok(Json(out))
}

#[utoipa::path(delete, path = "/api/git/config", tag = "Git", responses((status = 204, description = "Deleted")))]
pub async fn delete_config(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<StatusCode, StatusCode> {
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
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_SYNC)
        .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_GIT_CONFIGURE)
        .await?;
    let service = ctx.git_service();
    service
        .delete_config(workspace_id)
        .await
        .map_err(map_git_error)?;
    Ok(StatusCode::NO_CONTENT)
}
