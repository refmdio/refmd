use axum::{
    extract::{Path as AxumPath, Query, State},
    response::Response,
};
use uuid::Uuid;

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
use application::core::services::access;
use domain::access::permissions::PERM_DOC_VIEW;

use super::types::{FileByNameQuery, file_payload_response, map_file_error};

#[utoipa::path(
    get,
    path = "/api/files/{id}",
    tag = "Files",
    params(("id" = Uuid, Path, description = "File ID")),
    responses((status = 200, description = "OK", body = Vec<u8>, content_type = "application/octet-stream"))
)]
pub async fn get_file(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<Response, ApiError> {
    auth.ensure_permission(PERM_DOC_VIEW)?;
    let payload = ctx
        .file_service()
        .download_owned_file(auth.workspace_id, id)
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
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    AxumPath(filename): AxumPath<String>,
    Query(q): Query<FileByNameQuery>,
) -> Result<Response, ApiError> {
    auth.ensure_permission(PERM_DOC_VIEW)?;

    let actor = access::Actor::User(auth.user_id);
    let payload = ctx
        .file_service()
        .get_file_by_name(&actor, q.document_id, &filename)
        .await
        .map_err(map_file_error)?;
    Ok(file_payload_response(payload))
}
