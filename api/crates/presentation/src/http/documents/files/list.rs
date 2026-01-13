use axum::{
    Json,
    extract::{Path as AxumPath, State},
};
use base64::Engine;
use uuid::Uuid;

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
use domain::access::permissions::PERM_DOC_VIEW;

use super::types::{ListFileResponse, map_file_error};

/// List files for a document.
/// Returns encrypted metadata for client-side decryption to build file map.
#[utoipa::path(
    get,
    path = "/api/documents/{docId}/files",
    tag = "Files",
    params(("docId" = Uuid, Path, description = "Document ID")),
    responses((status = 200, description = "OK", body = Vec<ListFileResponse>))
)]
pub async fn list_files(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    AxumPath(doc_id): AxumPath<Uuid>,
) -> Result<Json<Vec<ListFileResponse>>, ApiError> {
    auth.ensure_permission(PERM_DOC_VIEW)?;

    let files = ctx
        .file_service()
        .list_files_for_document(auth.workspace_id, doc_id)
        .await
        .map_err(map_file_error)?;

    let response: Vec<ListFileResponse> = files
        .into_iter()
        .map(|f| ListFileResponse {
            id: f.id,
            encrypted_metadata: f
                .encrypted_metadata
                .map(|m| base64::engine::general_purpose::STANDARD.encode(m)),
            encrypted_metadata_nonce: f
                .encrypted_metadata_nonce
                .map(|n| base64::engine::general_purpose::STANDARD.encode(n)),
            encrypted_hash: f.encrypted_hash,
            size: f.size,
        })
        .collect();

    Ok(Json(response))
}
