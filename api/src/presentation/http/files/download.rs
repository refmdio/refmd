use axum::{
    extract::{Path as AxumPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use uuid::Uuid;

use crate::application::access;
use crate::domain::workspaces::permissions::PERM_DOC_VIEW;
use crate::presentation::context::AppContext;
use crate::presentation::http::auth::Bearer;
use crate::presentation::http::workspaces::scope as workspace_scope;

use super::types::{FileByNameQuery, file_payload_response, map_file_error};

#[utoipa::path(
    get,
    path = "/api/files/{id}",
    tag = "Files",
    params(("id" = Uuid, Path, description = "File ID")),
    responses((status = 200, description = "OK", body = Vec<u8>, content_type = "application/octet-stream"))
)]
pub async fn get_file(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<Response, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = crate::presentation::http::auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_DOC_VIEW)
        .await?;
    let payload = ctx
        .file_service()
        .download_owned_file(workspace_id, id)
        .await
        .map_err(map_file_error)?;
    Ok(file_payload_response(payload))
}

#[utoipa::path(
    get,
    path = "/api/files/documents/{filename}",
    tag = "Files",
    params(("filename" = String, Path, description = "File name"), ("document_id" = Uuid, Query, description = "Document ID")),
    responses((status = 200, description = "OK", body = Vec<u8>, content_type = "application/octet-stream"))
)]
pub async fn get_file_by_name(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    AxumPath(filename): AxumPath<String>,
    Query(q): Query<FileByNameQuery>,
) -> Result<Response, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_DOC_VIEW)
        .await?;

    let actor = access::Actor::User(user_id);
    let payload = ctx
        .file_service()
        .get_file_by_name(&actor, q.document_id, &filename)
        .await
        .map_err(map_file_error)?;
    Ok(file_payload_response(payload))
}
