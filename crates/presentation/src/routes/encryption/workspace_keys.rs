//! Workspace key routes: save/get KEK, KEK backup, KEK rotation

use application::types::{DeviceId, WorkspaceId};
use application::encryption::{
    CompleteKekRotationCommand, GetWorkspaceKekBackupQuery, GetWorkspaceKeyQuery,
    SaveWorkspaceKekBackupCommand, SaveWorkspaceKeyCommand,
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

/// Save workspace key request
#[derive(Debug, Deserialize, ToSchema)]
pub struct SaveWorkspaceKeyRequest {
    /// Device ID (required for multi-device support)
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub device_id: Uuid,
    /// Sender device ID (required for multi-device support)
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub sender_device_id: Uuid,
    /// Key version (optional, default: 1)
    #[schema(example = 1)]
    pub key_version: Option<u32>,
    /// Encrypted KEK (base64url encoded)
    #[schema(example = "base64url-encoded-encrypted-kek")]
    pub encrypted_kek: String,
    /// Encryption nonce (base64url encoded)
    #[schema(example = "base64url-encoded-nonce")]
    pub nonce: String,
    /// Whether this is the active key
    #[schema(example = true)]
    pub is_active: bool,
}

/// Workspace key response
#[derive(Debug, Serialize, ToSchema)]
pub struct WorkspaceKeyResponse {
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub workspace_id: String,
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub user_id: String,
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub device_id: String,
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub sender_device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_ecdh_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_signing_public_key: Option<String>,
    #[schema(example = 1)]
    pub key_version: i32,
    pub encrypted_kek: String,
    pub nonce: String,
    #[schema(example = true)]
    pub is_active: bool,
}

impl WorkspaceKeyResponse {
    fn from_key_dto(
        key: application::dto::WorkspaceEncryptedKeyDto,
        sender_ecdh_public_key: Option<&[u8]>,
        sender_signing_public_key: Option<&[u8]>,
    ) -> Self {
        Self {
            workspace_id: key.workspace_id.to_string(),
            user_id: key.user_id.to_string(),
            device_id: key.device_id.to_string(),
            sender_device_id: key.sender_device_id.to_string(),
            sender_ecdh_public_key: sender_ecdh_public_key.map(base64_url::encode),
            sender_signing_public_key: sender_signing_public_key.map(base64_url::encode),
            key_version: key.key_version,
            encrypted_kek: base64_url::encode(&key.encrypted_kek),
            nonce: base64_url::encode(&key.nonce),
            is_active: key.is_active,
        }
    }
}

/// Get workspace key query params
#[derive(Debug, Deserialize, ToSchema)]
pub struct GetWorkspaceKeyParams {
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub device_id: Uuid,
}

/// Complete KEK rotation request
#[derive(Debug, Deserialize, ToSchema)]
pub struct CompleteKekRotationRequest {
    #[schema(example = 2)]
    pub new_min_kek_version: i32,
}

/// Complete KEK rotation response
#[derive(Debug, Serialize, ToSchema)]
pub struct CompleteKekRotationResponse {
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub workspace_id: String,
    #[schema(example = 2)]
    pub new_min_kek_version: i32,
}

/// Save workspace KEK backup request (UMK-wrapped)
#[derive(Debug, Deserialize, ToSchema)]
pub struct SaveWorkspaceKekBackupRequest {
    #[schema(example = 1)]
    pub key_version: u32,
    pub encrypted_kek: String,
    pub nonce: String,
}

/// Workspace KEK backup response
#[derive(Debug, Serialize, ToSchema)]
pub struct WorkspaceKekBackupResponse {
    pub workspace_id: String,
    pub user_id: String,
    #[schema(example = 1)]
    pub key_version: i32,
    pub encrypted_kek: String,
    pub nonce: String,
}

impl From<application::dto::WorkspaceKekBackupDto> for WorkspaceKekBackupResponse {
    fn from(backup: application::dto::WorkspaceKekBackupDto) -> Self {
        Self {
            workspace_id: backup.workspace_id.to_string(),
            user_id: backup.user_id.to_string(),
            key_version: backup.key_version,
            encrypted_kek: base64_url::encode(&backup.encrypted_kek),
            nonce: base64_url::encode(&backup.nonce),
        }
    }
}

/// Save workspace key (KEK)
#[utoipa::path(
    post,
    path = "/api/encryption/workspaces/{workspace_id}/keys",
    request_body = SaveWorkspaceKeyRequest,
    params(("workspace_id" = Uuid, Path, description = "Workspace ID")),
    responses(
        (status = 201, description = "Key saved successfully", body = WorkspaceKeyResponse),
        (status = 400, description = "Invalid request", body = EncryptionErrorResponse),
        (status = 401, description = "Not authenticated", body = EncryptionErrorResponse),
        (status = 403, description = "Permission denied", body = EncryptionErrorResponse),
        (status = 409, description = "Key already exists", body = EncryptionErrorResponse),
    ),
    tag = "encryption"
)]
pub async fn save_workspace_key(
    State(state): State<EncryptionSubState>,
    pop_user: PopVerifiedUser,
    Path(workspace_id): Path<Uuid>,
    Json(request): Json<SaveWorkspaceKeyRequest>,
) -> impl IntoResponse {
    let (encrypted_kek, nonce) = try_decode!(decode_encrypted_key_nonce("encrypted_kek", &request.encrypted_kek, MAX_ENCRYPTED_KEY_BYTES, "nonce", &request.nonce), EncryptionErrorResponse);

    let handler = state.save_workspace_key_handler();

    let command = SaveWorkspaceKeyCommand {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        user_id: pop_user.user_id,
        device_id: DeviceId::from_uuid(request.device_id),
        sender_device_id: DeviceId::from_uuid(request.sender_device_id),
        authenticated_device_id: pop_user.device.id,
        key_version: request.key_version,
        encrypted_kek,
        nonce,
        is_active: request.is_active,
    };

    match handler.handle(command).await {
        Ok(result) => {
            let response = WorkspaceKeyResponse::from_key_dto(result.key, None, None);
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(e) => app_error_response!(e, EncryptionErrorResponse, conflict, bad_request, not_found, forbidden),
    }
}

/// Get workspace key (KEK)
#[utoipa::path(
    get,
    path = "/api/encryption/workspaces/{workspace_id}/keys",
    params(
        ("workspace_id" = Uuid, Path, description = "Workspace ID"),
        ("device_id" = Uuid, Query, description = "Device ID")
    ),
    responses(
        (status = 200, description = "Key found", body = WorkspaceKeyResponse),
        (status = 401, description = "Not authenticated", body = EncryptionErrorResponse),
        (status = 403, description = "Permission denied", body = EncryptionErrorResponse),
        (status = 404, description = "Key not found", body = EncryptionErrorResponse),
    ),
    tag = "encryption"
)]
pub async fn get_workspace_key(
    State(state): State<EncryptionSubState>,
    pop_user: PopVerifiedUser,
    Path(workspace_id): Path<Uuid>,
    axum::extract::Query(params): axum::extract::Query<GetWorkspaceKeyParams>,
) -> impl IntoResponse {
    let requested_device_id = DeviceId::from_uuid(params.device_id);

    let handler = state.get_workspace_key_handler();

    let query = GetWorkspaceKeyQuery {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        user_id: pop_user.user_id,
        device_id: requested_device_id,
        pop_verified_device_id: pop_user.device.id,
    };

    match handler.handle(query).await {
        Ok(result) => {
            let response = WorkspaceKeyResponse::from_key_dto(
                result.key,
                Some(&result.sender_ecdh_public_key),
                Some(&result.sender_signing_public_key),
            );
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => app_error_response!(e, EncryptionErrorResponse, not_found, forbidden),
    }
}

/// Complete KEK rotation
#[utoipa::path(
    post,
    path = "/api/encryption/workspaces/{workspace_id}/kek-rotation/complete",
    request_body = CompleteKekRotationRequest,
    params(("workspace_id" = Uuid, Path, description = "Workspace ID")),
    responses(
        (status = 200, description = "KEK rotation completed", body = CompleteKekRotationResponse),
        (status = 400, description = "Invalid request", body = EncryptionErrorResponse),
        (status = 401, description = "Not authenticated", body = EncryptionErrorResponse),
        (status = 403, description = "Permission denied", body = EncryptionErrorResponse),
        (status = 404, description = "Workspace not found", body = EncryptionErrorResponse),
    ),
    tag = "encryption"
)]
pub async fn complete_kek_rotation(
    State(state): State<EncryptionSubState>,
    pop_user: PopVerifiedUser,
    Path(workspace_id): Path<Uuid>,
    Json(request): Json<CompleteKekRotationRequest>,
) -> impl IntoResponse {
    let handler = state.complete_kek_rotation_handler();

    let command = CompleteKekRotationCommand {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        user_id: pop_user.user_id,
        new_min_kek_version: request.new_min_kek_version,
    };

    match handler.handle(command).await {
        Ok(result) => {
            let response = CompleteKekRotationResponse {
                workspace_id: result.workspace_id.to_string(),
                new_min_kek_version: result.new_min_kek_version,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => app_error_response!(e, EncryptionErrorResponse, bad_request, not_found, forbidden),
    }
}

/// Save workspace KEK backup (UMK-wrapped)
#[utoipa::path(
    post,
    path = "/api/encryption/workspaces/{workspace_id}/kek-backup",
    request_body = SaveWorkspaceKekBackupRequest,
    params(("workspace_id" = Uuid, Path, description = "Workspace ID")),
    responses(
        (status = 201, description = "Backup saved successfully", body = WorkspaceKekBackupResponse),
        (status = 400, description = "Invalid request", body = EncryptionErrorResponse),
        (status = 401, description = "Not authenticated", body = EncryptionErrorResponse),
        (status = 403, description = "Permission denied", body = EncryptionErrorResponse),
    ),
    tag = "encryption"
)]
pub async fn save_workspace_kek_backup(
    State(state): State<EncryptionSubState>,
    pop_user: PopVerifiedUser,
    Path(workspace_id): Path<Uuid>,
    Json(request): Json<SaveWorkspaceKekBackupRequest>,
) -> impl IntoResponse {
    let (encrypted_kek, nonce) = try_decode!(decode_encrypted_key_nonce("encrypted_kek", &request.encrypted_kek, MAX_ENCRYPTED_KEY_BYTES, "nonce", &request.nonce), EncryptionErrorResponse);

    let handler = state.save_workspace_kek_backup_handler();

    let command = SaveWorkspaceKekBackupCommand {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        user_id: pop_user.user_id,
        key_version: request.key_version,
        encrypted_kek,
        nonce,
    };

    match handler.handle(command).await {
        Ok(result) => {
            (StatusCode::CREATED, Json(WorkspaceKekBackupResponse::from(result.backup))).into_response()
        }
        Err(e) => app_error_response!(e, EncryptionErrorResponse, bad_request, not_found, forbidden),
    }
}

/// Get workspace KEK backup (UMK-wrapped)
#[utoipa::path(
    get,
    path = "/api/encryption/workspaces/{workspace_id}/kek-backup",
    params(("workspace_id" = Uuid, Path, description = "Workspace ID")),
    responses(
        (status = 200, description = "Backup found", body = WorkspaceKekBackupResponse),
        (status = 401, description = "Not authenticated", body = EncryptionErrorResponse),
        (status = 403, description = "Permission denied", body = EncryptionErrorResponse),
        (status = 404, description = "Backup not found", body = EncryptionErrorResponse),
    ),
    tag = "encryption"
)]
pub async fn get_workspace_kek_backup(
    State(state): State<EncryptionSubState>,
    pop_user: PopVerifiedUser,
    Path(workspace_id): Path<Uuid>,
) -> impl IntoResponse {
    let handler = state.get_workspace_kek_backup_handler();

    let query = GetWorkspaceKekBackupQuery {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        user_id: pop_user.user_id,
    };

    match handler.handle(query).await {
        Ok(result) => {
            (StatusCode::OK, Json(WorkspaceKekBackupResponse::from(result.backup))).into_response()
        }
        Err(e) => app_error_response!(e, EncryptionErrorResponse, not_found, forbidden),
    }
}
