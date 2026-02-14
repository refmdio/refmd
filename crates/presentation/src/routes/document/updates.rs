//! Document update routes: list updates, create update

use application::document::{
    CreateDocumentUpdateCommand, ListDocumentUpdatesQuery,
};
use application::types::DocumentId;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::DocumentSubState;
use crate::auth::PopVerifiedUser;
use crate::crypto_validation::{decode_b64_exact, decode_b64_max, decode_nonce};
use crate::try_decode;
use crate::routes::app_error_response;
use super::DocumentErrorResponse;

/// Maximum encrypted update data size (16 MB). Yjs updates can be large.
const MAX_UPDATE_DATA_BYTES: usize = 16 * 1024 * 1024;

/// Document update response (single update)
#[derive(Debug, Serialize, ToSchema)]
pub struct DocumentUpdateResponse {
    pub seq: i64,
    /// Base64url-encoded encrypted Yjs update binary
    pub update_data: String,
    /// Base64url-encoded 24-byte nonce
    pub nonce: String,
    /// DEK version used for encryption
    pub key_version: i32,
    /// Content-addressable hash for idempotency
    pub update_hash: String,
    /// Hash of the previous update (null for first update)
    pub prev_update_hash: Option<String>,
    /// Ed25519 signature (base64url)
    pub signature: String,
    /// Device that authored this update
    pub author_device_id: String,
    /// Client timestamp (milliseconds since epoch)
    pub timestamp: i64,
}

/// List document updates response
#[derive(Debug, Serialize, ToSchema)]
pub struct ListDocumentUpdatesResponse {
    pub updates: Vec<DocumentUpdateResponse>,
}

/// List document updates query params
#[derive(Debug, Deserialize, ToSchema)]
pub struct ListDocumentUpdatesParams {
    /// If provided, only return updates after this sequence number
    pub after_seq: Option<i64>,
}

/// Create document update request
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateDocumentUpdateRequest {
    /// Base64url-encoded encrypted Yjs update binary
    pub update_data: String,
    /// Base64url-encoded 24-byte nonce
    pub nonce: String,
    /// DEK version used for encryption
    pub key_version: i32,
    /// Content-addressable hash for idempotency (base64url)
    pub update_hash: String,
    /// Hash of the previous update for hash chain (base64url, nullable for first update)
    pub prev_update_hash: Option<String>,
    /// Ed25519 signature over the update (base64url)
    pub signature: String,
    /// Device that authored this update
    pub author_device_id: String,
    /// Client timestamp (milliseconds since epoch)
    pub timestamp: i64,
}

/// Create document update response
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateDocumentUpdateResponse {
    pub seq: i64,
}

/// List document updates (CRDT update log)
#[utoipa::path(
    get,
    path = "/api/documents/{document_id}/updates",
    params(
        ("document_id" = Uuid, Path, description = "Document ID"),
        ("after_seq" = Option<i64>, Query, description = "Only return updates after this sequence number"),
    ),
    responses(
        (status = 200, description = "List of encrypted document updates", body = ListDocumentUpdatesResponse),
        (status = 401, description = "Not authenticated", body = DocumentErrorResponse),
        (status = 403, description = "Permission denied", body = DocumentErrorResponse),
        (status = 404, description = "Document not found", body = DocumentErrorResponse),
    ),
    tag = "document"
)]
pub async fn list_updates(
    State(state): State<DocumentSubState>,
    Path(document_id): Path<Uuid>,
    Query(params): Query<ListDocumentUpdatesParams>,
    pop_user: PopVerifiedUser,
) -> impl IntoResponse {
    let handler = state.list_updates_handler();

    let query = ListDocumentUpdatesQuery {
        document_id: DocumentId::from_uuid(document_id),
        user_id: pop_user.user_id,
        after_seq: params.after_seq,
    };

    match handler.handle(query).await {
        Ok(result) => {
            let updates = result
                .updates
                .into_iter()
                .map(|u| DocumentUpdateResponse {
                    seq: u.seq,
                    update_data: base64_url::encode(&u.update_data),
                    nonce: base64_url::encode(&u.nonce),
                    key_version: u.key_version,
                    update_hash: u.update_hash,
                    prev_update_hash: u.prev_update_hash,
                    signature: base64_url::encode(&u.signature),
                    author_device_id: u.author_device_id.to_string(),
                    timestamp: u.timestamp,
                })
                .collect();
            (
                StatusCode::OK,
                Json(ListDocumentUpdatesResponse { updates }),
            )
                .into_response()
        }
        Err(e) => app_error_response!(e, DocumentErrorResponse, not_found, forbidden),
    }
}

/// Create a new document update (CRDT update)
#[utoipa::path(
    post,
    path = "/api/documents/{document_id}/updates",
    params(
        ("document_id" = Uuid, Path, description = "Document ID"),
    ),
    request_body = CreateDocumentUpdateRequest,
    responses(
        (status = 201, description = "Document update created", body = CreateDocumentUpdateResponse),
        (status = 400, description = "Bad request (invalid nonce, encoding)", body = DocumentErrorResponse),
        (status = 401, description = "Not authenticated", body = DocumentErrorResponse),
        (status = 403, description = "Permission denied", body = DocumentErrorResponse),
        (status = 404, description = "Document not found", body = DocumentErrorResponse),
        (status = 409, description = "Document is archived", body = DocumentErrorResponse),
    ),
    tag = "document"
)]
pub async fn create_update(
    State(state): State<DocumentSubState>,
    Path(document_id): Path<Uuid>,
    pop_user: PopVerifiedUser,
    Json(request): Json<CreateDocumentUpdateRequest>,
) -> impl IntoResponse {
    // Decode update_data (max 16 MB)
    let update_data = try_decode!(
        decode_b64_max("update_data", &request.update_data, MAX_UPDATE_DATA_BYTES),
        DocumentErrorResponse
    );

    // Decode nonce (24 bytes, XChaCha20-Poly1305)
    let nonce = try_decode!(
        decode_nonce("nonce", &request.nonce),
        DocumentErrorResponse
    );

    let handler = state.create_update_handler();

    // Decode signature (64 bytes for Ed25519)
    let signature = try_decode!(
        decode_b64_exact("signature", &request.signature, 64),
        DocumentErrorResponse
    );

    // Parse author_device_id
    let author_device_id = try_decode!(
        crate::crypto_validation::parse_device_id("author_device_id", &request.author_device_id),
        DocumentErrorResponse
    );

    let command = CreateDocumentUpdateCommand {
        document_id: DocumentId::from_uuid(document_id),
        user_id: pop_user.user_id,
        update_data,
        nonce,
        key_version: request.key_version,
        update_hash: request.update_hash,
        prev_update_hash: request.prev_update_hash,
        signature,
        author_device_id,
        timestamp: request.timestamp,
    };

    match handler.handle(command).await {
        Ok(result) => (
            StatusCode::CREATED,
            Json(CreateDocumentUpdateResponse { seq: result.seq }),
        )
            .into_response(),
        Err(e) => app_error_response!(e, DocumentErrorResponse, conflict, bad_request, not_found, forbidden),
    }
}
