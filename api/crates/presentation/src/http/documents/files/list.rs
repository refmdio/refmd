use axum::{
    Json,
    extract::{Path as AxumPath, Query, State},
    http::HeaderMap,
};
use base64::Engine;
use uuid::Uuid;

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::security::token;

use super::types::{ListFileResponse, map_file_error};

#[derive(Debug, serde::Deserialize)]
pub struct ListFilesQuery {
    pub token: Option<String>,
}

/// List files for a document.
/// Returns encrypted metadata for client-side decryption to build file map.
/// Supports authentication via bearer token or share token query parameter.
#[utoipa::path(
    get,
    path = "/api/documents/{docId}/files",
    tag = "Files",
    params(
        ("docId" = Uuid, Path, description = "Document ID"),
        ("token" = Option<String>, Query, description = "Share token for authentication")
    ),
    responses((status = 200, description = "OK", body = Vec<ListFileResponse>))
)]
pub async fn list_files(
    State(ctx): State<DocumentsContext>,
    headers: HeaderMap,
    Query(query): Query<ListFilesQuery>,
    AxumPath(doc_id): AxumPath<Uuid>,
) -> Result<Json<Vec<ListFileResponse>>, ApiError> {
    let share_token = query.token.as_deref();
    let bearer = token::bearer_from_headers(&headers);

    let actor = token::resolve_actor_from_parts(&ctx, bearer, share_token)
        .await
        .map_err(token::map_actor_error)?
        .ok_or(ApiError::unauthorized("unauthorized"))?;

    let files = ctx
        .file_service()
        .list_files_for_actor(&actor, doc_id)
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
