use axum::{extract::State, http::StatusCode, Json};
use uuid::Uuid;

use crate::context::IdentityContext;
use crate::http::error::ApiError;
use crate::http::extractors::AuthedUser;
use application::core::services::errors::ServiceError;

use super::types::{
    EncryptedPrivateKeyResponse, MasterKeyBackupResponse, RegisterPublicKeyRequest,
    StoreEncryptedPrivateKeyRequest, StoreMasterKeyBackupRequest, UserPublicKeyResponse,
};

fn map_keys_error(err: ServiceError) -> ApiError {
    crate::http::error::map_service_error(err, "user_keys_service_error")
}

// ============================================================================
// Public Key Endpoints
// ============================================================================

#[utoipa::path(
    post,
    path = "/api/me/keys",
    tag = "E2EE",
    request_body = RegisterPublicKeyRequest,
    responses((status = 200, body = UserPublicKeyResponse))
)]
pub async fn register_public_key(
    State(ctx): State<IdentityContext>,
    auth: AuthedUser,
    Json(payload): Json<RegisterPublicKeyRequest>,
) -> Result<Json<UserPublicKeyResponse>, ApiError> {
    let (public_key, key_type) = payload
        .decode()
        .map_err(|e| ApiError::bad_request(e))?;

    let service = ctx.user_keys_service();
    let dto = service
        .register_public_key(auth.user_id, public_key, key_type)
        .await
        .map_err(map_keys_error)?;

    Ok(Json(UserPublicKeyResponse::from(dto)))
}

#[utoipa::path(
    get,
    path = "/api/me/keys",
    tag = "E2EE",
    responses(
        (status = 200, body = UserPublicKeyResponse),
        (status = 404, description = "Public key not found")
    )
)]
pub async fn get_my_public_key(
    State(ctx): State<IdentityContext>,
    auth: AuthedUser,
) -> Result<Json<UserPublicKeyResponse>, ApiError> {
    let service = ctx.user_keys_service();
    let dto = service
        .get_public_key(auth.user_id)
        .await
        .map_err(map_keys_error)?
        .ok_or_else(|| ApiError::not_found("public_key_not_found"))?;

    Ok(Json(UserPublicKeyResponse::from(dto)))
}

#[utoipa::path(
    get,
    path = "/api/users/{user_id}/keys",
    tag = "E2EE",
    params(("user_id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 200, body = UserPublicKeyResponse),
        (status = 404, description = "Public key not found")
    )
)]
pub async fn get_user_public_key(
    State(ctx): State<IdentityContext>,
    _auth: AuthedUser,
    axum::extract::Path(user_id): axum::extract::Path<Uuid>,
) -> Result<Json<UserPublicKeyResponse>, ApiError> {
    let service = ctx.user_keys_service();
    let dto = service
        .get_public_key(user_id)
        .await
        .map_err(map_keys_error)?
        .ok_or_else(|| ApiError::not_found("public_key_not_found"))?;

    Ok(Json(UserPublicKeyResponse::from(dto)))
}

// ============================================================================
// Master Key Backup Endpoints
// ============================================================================

#[utoipa::path(
    post,
    path = "/api/me/master-key/backup",
    tag = "E2EE",
    request_body = StoreMasterKeyBackupRequest,
    responses((status = 200, body = MasterKeyBackupResponse))
)]
pub async fn store_master_key_backup(
    State(ctx): State<IdentityContext>,
    auth: AuthedUser,
    Json(payload): Json<StoreMasterKeyBackupRequest>,
) -> Result<Json<MasterKeyBackupResponse>, ApiError> {
    let (encrypted_key, salt, kdf_type, kdf_params) = payload
        .decode()
        .map_err(|e| ApiError::bad_request(e))?;

    let service = ctx.user_keys_service();
    let dto = service
        .store_master_key_backup(auth.user_id, encrypted_key, salt, kdf_type, kdf_params)
        .await
        .map_err(map_keys_error)?;

    Ok(Json(MasterKeyBackupResponse::from(dto)))
}

#[utoipa::path(
    get,
    path = "/api/me/master-key/backup",
    tag = "E2EE",
    responses(
        (status = 200, body = MasterKeyBackupResponse),
        (status = 404, description = "Master key backup not found")
    )
)]
pub async fn get_master_key_backup(
    State(ctx): State<IdentityContext>,
    auth: AuthedUser,
) -> Result<Json<MasterKeyBackupResponse>, ApiError> {
    let service = ctx.user_keys_service();
    let dto = service
        .get_master_key_backup(auth.user_id)
        .await
        .map_err(map_keys_error)?
        .ok_or_else(|| ApiError::not_found("master_key_backup_not_found"))?;

    Ok(Json(MasterKeyBackupResponse::from(dto)))
}

// ============================================================================
// Encrypted Private Key Endpoints
// ============================================================================

#[utoipa::path(
    post,
    path = "/api/me/private-key/encrypted",
    tag = "E2EE",
    request_body = StoreEncryptedPrivateKeyRequest,
    responses((status = 200, body = EncryptedPrivateKeyResponse))
)]
pub async fn store_encrypted_private_key(
    State(ctx): State<IdentityContext>,
    auth: AuthedUser,
    Json(payload): Json<StoreEncryptedPrivateKeyRequest>,
) -> Result<Json<EncryptedPrivateKeyResponse>, ApiError> {
    let (encrypted_private_key, nonce) = payload
        .decode()
        .map_err(|e| ApiError::bad_request(e))?;

    let service = ctx.user_keys_service();
    let dto = service
        .store_encrypted_private_key(auth.user_id, encrypted_private_key, nonce)
        .await
        .map_err(map_keys_error)?;

    Ok(Json(EncryptedPrivateKeyResponse::from(dto)))
}

#[utoipa::path(
    get,
    path = "/api/me/private-key/encrypted",
    tag = "E2EE",
    responses(
        (status = 200, body = EncryptedPrivateKeyResponse),
        (status = 404, description = "Encrypted private key not found")
    )
)]
pub async fn get_encrypted_private_key(
    State(ctx): State<IdentityContext>,
    auth: AuthedUser,
) -> Result<Json<EncryptedPrivateKeyResponse>, ApiError> {
    let service = ctx.user_keys_service();
    let dto = service
        .get_encrypted_private_key(auth.user_id)
        .await
        .map_err(map_keys_error)?
        .ok_or_else(|| ApiError::not_found("encrypted_private_key_not_found"))?;

    Ok(Json(EncryptedPrivateKeyResponse::from(dto)))
}

// ============================================================================
// E2EE Setup Status
// ============================================================================

#[utoipa::path(
    post,
    path = "/api/me/encryption/setup-complete",
    tag = "E2EE",
    responses((status = 204))
)]
pub async fn mark_encryption_setup_complete(
    State(ctx): State<IdentityContext>,
    auth: AuthedUser,
) -> Result<StatusCode, ApiError> {
    let service = ctx.user_keys_service();
    service
        .mark_encryption_setup_completed(auth.user_id)
        .await
        .map_err(map_keys_error)?;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/me/encryption/status",
    tag = "E2EE",
    responses((status = 200, body = EncryptionStatusResponse))
)]
pub async fn get_encryption_status(
    State(ctx): State<IdentityContext>,
    auth: AuthedUser,
) -> Result<Json<EncryptionStatusResponse>, ApiError> {
    let service = ctx.user_keys_service();
    let is_setup = service
        .is_encryption_setup_completed(auth.user_id)
        .await
        .map_err(map_keys_error)?;

    Ok(Json(EncryptionStatusResponse { is_setup_completed: is_setup }))
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionStatusResponse {
    pub is_setup_completed: bool,
}
