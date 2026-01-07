use axum::{extract::State, Json};
use uuid::Uuid;

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
use application::core::services::errors::ServiceError;

use super::types::{
    DocumentKeyResponse, RotateDocumentKeyRequest, RotateDocumentKeyResponse, ShareKeyResponse,
    ShareSaltResponse, StoreDocumentKeyRequest, StorePasswordProtectedShareKeyRequest,
    StoreShareKeyRequest,
};

fn map_keys_error(err: ServiceError) -> ApiError {
    crate::http::error::map_service_error(err, "document_keys_service_error")
}

// ============================================================================
// Document Key Endpoints
// ============================================================================

#[utoipa::path(
    get,
    path = "/api/documents/{id}/keys",
    tag = "E2EE",
    params(("id" = Uuid, Path, description = "Document ID")),
    responses(
        (status = 200, body = DocumentKeyResponse),
        (status = 404, description = "Document key not found")
    )
)]
pub async fn get_document_key(
    State(ctx): State<DocumentsContext>,
    _auth: WorkspaceAuth,
    axum::extract::Path(document_id): axum::extract::Path<Uuid>,
) -> Result<Json<DocumentKeyResponse>, ApiError> {
    let service = ctx.document_keys_service();
    let dto = service
        .get_document_key(document_id)
        .await
        .map_err(map_keys_error)?
        .ok_or_else(|| ApiError::not_found("document_key_not_found"))?;

    Ok(Json(DocumentKeyResponse::from(dto)))
}

#[utoipa::path(
    post,
    path = "/api/documents/{id}/keys",
    tag = "E2EE",
    params(("id" = Uuid, Path, description = "Document ID")),
    request_body = StoreDocumentKeyRequest,
    responses((status = 200, body = DocumentKeyResponse))
)]
pub async fn store_document_key(
    State(ctx): State<DocumentsContext>,
    _auth: WorkspaceAuth,
    axum::extract::Path(document_id): axum::extract::Path<Uuid>,
    Json(payload): Json<StoreDocumentKeyRequest>,
) -> Result<Json<DocumentKeyResponse>, ApiError> {
    let (encrypted_dek, nonce) = payload
        .decode()
        .map_err(|e| ApiError::bad_request(e))?;

    let service = ctx.document_keys_service();
    let dto = service
        .store_document_key(document_id, encrypted_dek, nonce, payload.key_version)
        .await
        .map_err(map_keys_error)?;

    Ok(Json(DocumentKeyResponse::from(dto)))
}

// ============================================================================
// Share Key Endpoints
// ============================================================================

#[utoipa::path(
    get,
    path = "/api/shares/{id}/keys",
    tag = "E2EE",
    params(("id" = Uuid, Path, description = "Share ID")),
    responses(
        (status = 200, body = ShareKeyResponse),
        (status = 404, description = "Share key not found")
    )
)]
pub async fn get_share_key(
    State(ctx): State<DocumentsContext>,
    axum::extract::Path(share_id): axum::extract::Path<Uuid>,
) -> Result<Json<ShareKeyResponse>, ApiError> {
    let service = ctx.document_keys_service();
    let dto = service
        .get_share_key(share_id)
        .await
        .map_err(map_keys_error)?
        .ok_or_else(|| ApiError::not_found("share_key_not_found"))?;

    Ok(Json(ShareKeyResponse::from(dto)))
}

#[utoipa::path(
    get,
    path = "/api/shares/{id}/salt",
    tag = "E2EE",
    params(("id" = Uuid, Path, description = "Share ID")),
    responses((status = 200, body = ShareSaltResponse))
)]
pub async fn get_share_salt(
    State(ctx): State<DocumentsContext>,
    axum::extract::Path(share_id): axum::extract::Path<Uuid>,
) -> Result<Json<ShareSaltResponse>, ApiError> {
    use base64::Engine;
    let service = ctx.document_keys_service();
    let salt = service
        .get_share_salt(share_id)
        .await
        .map_err(map_keys_error)?;

    Ok(Json(ShareSaltResponse {
        share_id,
        salt: salt.map(|s| base64::engine::general_purpose::STANDARD.encode(&s)),
    }))
}

#[utoipa::path(
    post,
    path = "/api/shares/{id}/keys",
    tag = "E2EE",
    params(("id" = Uuid, Path, description = "Share ID")),
    request_body = StoreShareKeyRequest,
    responses((status = 200, body = ShareKeyResponse))
)]
pub async fn store_share_key(
    State(ctx): State<DocumentsContext>,
    _auth: WorkspaceAuth,
    axum::extract::Path(share_id): axum::extract::Path<Uuid>,
    Json(payload): Json<StoreShareKeyRequest>,
) -> Result<Json<ShareKeyResponse>, ApiError> {
    let encrypted_dek = payload
        .decode()
        .map_err(|e| ApiError::bad_request(e))?;

    let service = ctx.document_keys_service();
    let dto = service
        .store_share_key(share_id, encrypted_dek)
        .await
        .map_err(map_keys_error)?;

    Ok(Json(ShareKeyResponse::from(dto)))
}

#[utoipa::path(
    post,
    path = "/api/shares/{id}/keys/password-protected",
    tag = "E2EE",
    params(("id" = Uuid, Path, description = "Share ID")),
    request_body = StorePasswordProtectedShareKeyRequest,
    responses((status = 200, body = ShareKeyResponse))
)]
pub async fn store_password_protected_share_key(
    State(ctx): State<DocumentsContext>,
    _auth: WorkspaceAuth,
    axum::extract::Path(share_id): axum::extract::Path<Uuid>,
    Json(payload): Json<StorePasswordProtectedShareKeyRequest>,
) -> Result<Json<ShareKeyResponse>, ApiError> {
    let (encrypted_dek, salt, kdf_params) = payload
        .decode()
        .map_err(|e| ApiError::bad_request(e))?;

    let service = ctx.document_keys_service();
    let dto = service
        .store_password_protected_share_key(share_id, encrypted_dek, salt, kdf_params)
        .await
        .map_err(map_keys_error)?;

    Ok(Json(ShareKeyResponse::from(dto)))
}

// ============================================================================
// Document Key Rotation
// ============================================================================

#[utoipa::path(
    post,
    path = "/api/documents/{id}/keys/rotate",
    tag = "E2EE",
    params(("id" = Uuid, Path, description = "Document ID")),
    request_body = RotateDocumentKeyRequest,
    responses(
        (status = 200, body = RotateDocumentKeyResponse),
        (status = 400, description = "Invalid request"),
        (status = 403, description = "Permission denied")
    )
)]
pub async fn rotate_document_key(
    State(ctx): State<DocumentsContext>,
    _auth: WorkspaceAuth,
    axum::extract::Path(document_id): axum::extract::Path<Uuid>,
    Json(payload): Json<RotateDocumentKeyRequest>,
) -> Result<Json<RotateDocumentKeyResponse>, ApiError> {
    let (encrypted_dek, nonce) = payload
        .decode()
        .map_err(|e| ApiError::bad_request(e))?;

    let service = ctx.document_keys_service();
    let new_version = service
        .rotate_document_key(document_id, encrypted_dek, nonce)
        .await
        .map_err(map_keys_error)?;

    Ok(Json(RotateDocumentKeyResponse {
        document_id,
        new_key_version: new_version,
    }))
}
