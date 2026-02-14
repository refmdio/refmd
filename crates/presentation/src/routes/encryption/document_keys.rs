//! Document key routes: save/get DEK

use application::types::DocumentId;
use application::encryption::{
    GetDocumentKeyQuery, SaveDocumentKeyCommand,
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::EncryptionSubState;
use crate::auth::PopVerifiedUser;
use crate::crypto_validation::{MAX_ENCRYPTED_KEY_BYTES, decode_encrypted_key_nonce};
use crate::try_decode;
use crate::routes::app_error_response;
use super::EncryptionErrorResponse;

/// Save document key request
#[derive(Debug, Deserialize, ToSchema)]
pub struct SaveDocumentKeyRequest {
    #[schema(example = 1)]
    pub key_version: Option<u32>,
    pub encrypted_dek: String,
    pub nonce: String,
    #[schema(example = true)]
    pub is_active: bool,
}

/// Document key response
#[derive(Debug, Serialize, ToSchema)]
pub struct DocumentKeyResponse {
    pub document_id: String,
    #[schema(example = 1)]
    pub key_version: i32,
    pub encrypted_dek: String,
    pub nonce: String,
    #[schema(example = true)]
    pub is_active: bool,
}

impl From<application::dto::DocumentEncryptedKeyDto> for DocumentKeyResponse {
    fn from(key: application::dto::DocumentEncryptedKeyDto) -> Self {
        Self {
            document_id: key.document_id.to_string(),
            key_version: key.key_version,
            encrypted_dek: base64_url::encode(&key.encrypted_dek),
            nonce: base64_url::encode(&key.nonce),
            is_active: key.is_active,
        }
    }
}

/// Save document key (DEK)
#[utoipa::path(
    post,
    path = "/api/encryption/documents/{document_id}/keys",
    request_body = SaveDocumentKeyRequest,
    params(("document_id" = Uuid, Path, description = "Document ID")),
    responses(
        (status = 201, description = "Key saved successfully", body = DocumentKeyResponse),
        (status = 400, description = "Invalid request", body = EncryptionErrorResponse),
        (status = 401, description = "Not authenticated", body = EncryptionErrorResponse),
        (status = 403, description = "Permission denied", body = EncryptionErrorResponse),
        (status = 404, description = "Document not found", body = EncryptionErrorResponse),
    ),
    tag = "encryption"
)]
pub async fn save_document_key(
    State(state): State<EncryptionSubState>,
    pop_user: PopVerifiedUser,
    Path(document_id): Path<Uuid>,
    Json(request): Json<SaveDocumentKeyRequest>,
) -> impl IntoResponse {
    let (encrypted_dek, nonce) = try_decode!(decode_encrypted_key_nonce("encrypted_dek", &request.encrypted_dek, MAX_ENCRYPTED_KEY_BYTES, "nonce", &request.nonce), EncryptionErrorResponse);

    let handler = state.save_document_key_handler();

    let command = SaveDocumentKeyCommand {
        document_id: DocumentId::from_uuid(document_id),
        user_id: pop_user.user_id,
        key_version: request.key_version,
        encrypted_dek,
        nonce,
        is_active: request.is_active,
    };

    match handler.handle(command).await {
        Ok(result) => {
            (StatusCode::CREATED, Json(DocumentKeyResponse::from(result.key))).into_response()
        }
        Err(e) => app_error_response!(e, EncryptionErrorResponse, bad_request, not_found, forbidden),
    }
}

/// Get document key (DEK)
#[utoipa::path(
    get,
    path = "/api/encryption/documents/{document_id}/keys",
    params(("document_id" = Uuid, Path, description = "Document ID")),
    responses(
        (status = 200, description = "Key found", body = DocumentKeyResponse),
        (status = 401, description = "Not authenticated", body = EncryptionErrorResponse),
        (status = 403, description = "Permission denied", body = EncryptionErrorResponse),
        (status = 404, description = "Key not found", body = EncryptionErrorResponse),
    ),
    tag = "encryption"
)]
pub async fn get_document_key(
    State(state): State<EncryptionSubState>,
    pop_user: PopVerifiedUser,
    Path(document_id): Path<Uuid>,
) -> impl IntoResponse {
    let handler = state.get_document_key_handler();

    let query = GetDocumentKeyQuery {
        document_id: DocumentId::from_uuid(document_id),
        user_id: pop_user.user_id,
    };

    match handler.handle(query).await {
        Ok(result) => {
            (StatusCode::OK, Json(DocumentKeyResponse::from(result.key))).into_response()
        }
        Err(e) => app_error_response!(e, EncryptionErrorResponse, not_found, forbidden),
    }
}
