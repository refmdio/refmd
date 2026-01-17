use axum::{
    extract::{Path as AxumPath, Query, State},
    http::HeaderMap,
    response::Response,
};
use uuid::Uuid;

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::security::token;

use super::types::{file_payload_response, map_file_error};

#[derive(Debug, serde::Deserialize)]
pub struct GetFileQuery {
    pub token: Option<String>,
}

/// Download a file by ID.
/// Returns encrypted file with E2EE metadata in headers for client-side decryption.
/// Supports authentication via bearer token or share token query parameter.
#[utoipa::path(
    get,
    path = "/api/files/{id}",
    tag = "Files",
    params(
        ("id" = Uuid, Path, description = "File ID"),
        ("token" = Option<String>, Query, description = "Share token for authentication")
    ),
    responses((status = 200, description = "OK", body = Vec<u8>, content_type = "application/octet-stream"))
)]
pub async fn get_file(
    State(ctx): State<DocumentsContext>,
    headers: HeaderMap,
    Query(query): Query<GetFileQuery>,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<Response, ApiError> {
    let share_token = query.token.as_deref();
    let bearer = token::bearer_from_headers(&headers);

    let actor = token::resolve_actor_from_parts(&ctx, bearer, share_token)
        .await
        .map_err(token::map_actor_error)?
        .ok_or(ApiError::unauthorized("unauthorized"))?;

    let payload = ctx
        .file_service()
        .download_file_for_actor(&actor, id)
        .await
        .map_err(map_file_error)?;

    Ok(file_payload_response(payload))
}
