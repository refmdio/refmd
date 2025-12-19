use axum::{Json, extract::State};
use uuid::Uuid;

use crate::context::GitContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceUser;
use application::core::services::errors::ServiceError;

use super::types::{
    AddPatternsRequest, CheckIgnoredRequest, GitignoreUpdateResponse, map_git_error,
};

#[utoipa::path(post, path = "/api/git/ignore/doc/{id}", params(("id" = String, Path, description = "Document ID")), tag = "Git", responses((status = 200, description = "OK")))]
pub async fn ignore_document(
    State(ctx): State<GitContext>,
    auth: WorkspaceUser,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<GitignoreUpdateResponse>, ApiError> {
    let doc_id = Uuid::parse_str(&id).map_err(|_| ApiError::bad_request("invalid_document_id"))?;
    let service = ctx.git_service();
    let res = service
        .ignore_document(auth.workspace_id, doc_id)
        .await
        .map_err(|err| match err {
            ServiceError::NotFound => ApiError::not_found("not_found"),
            other => map_git_error(other),
        })?;
    Ok(Json(res.into()))
}

#[utoipa::path(post, path = "/api/git/ignore/folder/{id}", params(("id" = String, Path, description = "Folder ID")), tag = "Git", responses((status = 200, description = "OK")))]
pub async fn ignore_folder(
    State(ctx): State<GitContext>,
    auth: WorkspaceUser,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<GitignoreUpdateResponse>, ApiError> {
    let folder_id = Uuid::parse_str(&id).map_err(|_| ApiError::bad_request("invalid_folder_id"))?;
    let service = ctx.git_service();
    let res = service
        .ignore_folder(auth.workspace_id, folder_id)
        .await
        .map_err(|err| match err {
            ServiceError::NotFound => ApiError::not_found("not_found"),
            other => map_git_error(other),
        })?;
    Ok(Json(res.into()))
}

#[utoipa::path(post, path = "/api/git/gitignore/patterns", tag = "Git", request_body = AddPatternsRequest, responses((status = 200, description = "OK")))]
pub async fn add_gitignore_patterns(
    State(ctx): State<GitContext>,
    auth: WorkspaceUser,
    Json(req): Json<AddPatternsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let service = ctx.git_service();
    let added = service
        .add_gitignore_patterns(auth.workspace_id, req.patterns)
        .await
        .map_err(map_git_error)?;
    Ok(Json(serde_json::json!({"added": added})))
}

#[utoipa::path(get, path = "/api/git/gitignore/patterns", tag = "Git", responses((status = 200, description = "OK")))]
pub async fn get_gitignore_patterns(
    State(ctx): State<GitContext>,
    auth: WorkspaceUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    let service = ctx.git_service();
    let patterns = service
        .get_gitignore_patterns(auth.workspace_id)
        .await
        .map_err(map_git_error)?;
    Ok(Json(serde_json::json!({"patterns": patterns})))
}

#[utoipa::path(post, path = "/api/git/gitignore/check", tag = "Git", request_body = CheckIgnoredRequest, responses((status = 200, description = "OK")))]
pub async fn check_path_ignored(
    State(ctx): State<GitContext>,
    auth: WorkspaceUser,
    Json(req): Json<CheckIgnoredRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let service = ctx.git_service();
    let is_ignored = service
        .check_path_ignored(auth.workspace_id, &req.path)
        .await
        .map_err(map_git_error)?;
    Ok(Json(
        serde_json::json!({"path": req.path, "is_ignored": is_ignored}),
    ))
}
