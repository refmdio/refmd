use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use uuid::Uuid;

use crate::context::AppContext;
use crate::http::workspaces::scope as workspace_scope;
use crate::security::token::{self, Bearer};
use application::core::services::errors::ServiceError;

use super::types::{
    AddPatternsRequest, CheckIgnoredRequest, GitignoreUpdateResponse, map_git_error,
};

#[utoipa::path(post, path = "/api/git/ignore/doc/{id}", params(("id" = String, Path, description = "Document ID")), tag = "Git", responses((status = 200, description = "OK")))]
pub async fn ignore_document(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<GitignoreUpdateResponse>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let doc_id = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let service = ctx.git_service();
    let res = service
        .ignore_document(workspace_id, doc_id)
        .await
        .map_err(|err| match err {
            ServiceError::NotFound => StatusCode::NOT_FOUND,
            other => map_git_error(other),
        })?;
    Ok(Json(res.into()))
}

#[utoipa::path(post, path = "/api/git/ignore/folder/{id}", params(("id" = String, Path, description = "Folder ID")), tag = "Git", responses((status = 200, description = "OK")))]
pub async fn ignore_folder(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<GitignoreUpdateResponse>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let folder_id = Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let service = ctx.git_service();
    let res = service
        .ignore_folder(workspace_id, folder_id)
        .await
        .map_err(|err| match err {
            ServiceError::NotFound => StatusCode::NOT_FOUND,
            other => map_git_error(other),
        })?;
    Ok(Json(res.into()))
}

#[utoipa::path(post, path = "/api/git/gitignore/patterns", tag = "Git", request_body = AddPatternsRequest, responses((status = 200, description = "OK")))]
pub async fn add_gitignore_patterns(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Json(req): Json<AddPatternsRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let service = ctx.git_service();
    let added = service
        .add_gitignore_patterns(workspace_id, req.patterns)
        .await
        .map_err(map_git_error)?;
    Ok(Json(serde_json::json!({"added": added})))
}

#[utoipa::path(get, path = "/api/git/gitignore/patterns", tag = "Git", responses((status = 200, description = "OK")))]
pub async fn get_gitignore_patterns(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let service = ctx.git_service();
    let patterns = service
        .get_gitignore_patterns(workspace_id)
        .await
        .map_err(map_git_error)?;
    Ok(Json(serde_json::json!({"patterns": patterns})))
}

#[utoipa::path(post, path = "/api/git/gitignore/check", tag = "Git", request_body = CheckIgnoredRequest, responses((status = 200, description = "OK")))]
pub async fn check_path_ignored(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Json(req): Json<CheckIgnoredRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let service = ctx.git_service();
    let is_ignored = service
        .check_path_ignored(workspace_id, &req.path)
        .await
        .map_err(map_git_error)?;
    Ok(Json(
        serde_json::json!({"path": req.path, "is_ignored": is_ignored}),
    ))
}
