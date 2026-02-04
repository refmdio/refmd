//! Encryption key routes (KEK/DEK)
//!
//! These routes handle E2EE key material and require PoP (Proof of Possession)
//! verification per ADR-009.

/// XChaCha20-Poly1305 nonce size in bytes
const XCHACHA20_NONCE_SIZE: usize = 24;

use application::domain::document::{DocumentRepository, DocumentUpdateRepository};
use application::domain::encryption::{
    DeviceEncryptedUMKRepository, DeviceId, DeviceRepository, DocumentEncryptedKeyRepository,
    PendingDeviceRepository, UserEncryptedIdentityKeyRepository, UserEncryptedMasterKeyRepository,
    UserIdentityPublicKeyRepository, WorkspaceEncryptedKeyRepository,
};
use application::domain::identity::{SessionRepository, UserRepository, UserSettingsRepository};
use application::domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRoleRepository,
};
use application::encryption::{
    GetDocumentKeyHandler, GetDocumentKeyQuery, GetWorkspaceKeyHandler, GetWorkspaceKeyQuery,
    SaveDocumentKeyCommand, SaveDocumentKeyHandler, SaveWorkspaceKeyCommand,
    SaveWorkspaceKeyHandler,
};
use application::identity::RegistrationService;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::auth::verify_pop;

/// Create encryption routes
pub fn routes<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    state: AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
) -> Router
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    Router::new()
        // Workspace KEK endpoints
        .route(
            "/workspaces/{workspace_id}/keys",
            post(save_workspace_key::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>)
                .get(get_workspace_key::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>),
        )
        // Document DEK endpoints
        .route(
            "/documents/{document_id}/keys",
            post(save_document_key::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>)
                .get(get_document_key::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>),
        )
        .with_state(state)
}

// ============ Request/Response Types ============

/// Save workspace key request
#[derive(Debug, Deserialize, ToSchema)]
pub struct SaveWorkspaceKeyRequest {
    /// Device ID (optional, for multi-device support)
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub device_id: Option<Uuid>,
    /// Sender device ID (optional, for multi-device support)
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub sender_device_id: Option<Uuid>,
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
    /// Workspace ID
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub workspace_id: String,
    /// User ID
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub user_id: String,
    /// Device ID (optional)
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Sender device ID (optional)
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_device_id: Option<String>,
    /// Key version
    #[schema(example = 1)]
    pub key_version: i32,
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

/// Get workspace key query params
#[derive(Debug, Deserialize, ToSchema)]
pub struct GetWorkspaceKeyParams {
    /// Device ID (optional)
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub device_id: Option<Uuid>,
}

/// Save document key request
#[derive(Debug, Deserialize, ToSchema)]
pub struct SaveDocumentKeyRequest {
    /// Key version (optional, default: 1)
    #[schema(example = 1)]
    pub key_version: Option<u32>,
    /// Encrypted DEK (base64url encoded)
    #[schema(example = "base64url-encoded-encrypted-dek")]
    pub encrypted_dek: String,
    /// Encryption nonce (base64url encoded)
    #[schema(example = "base64url-encoded-nonce")]
    pub nonce: String,
    /// Whether this is the active key
    #[schema(example = true)]
    pub is_active: bool,
}

/// Document key response
#[derive(Debug, Serialize, ToSchema)]
pub struct DocumentKeyResponse {
    /// Document ID
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub document_id: String,
    /// Key version
    #[schema(example = 1)]
    pub key_version: i32,
    /// Encrypted DEK (base64url encoded)
    #[schema(example = "base64url-encoded-encrypted-dek")]
    pub encrypted_dek: String,
    /// Encryption nonce (base64url encoded)
    #[schema(example = "base64url-encoded-nonce")]
    pub nonce: String,
    /// Whether this is the active key
    #[schema(example = true)]
    pub is_active: bool,
}

/// Error response
#[derive(Debug, Serialize, ToSchema)]
pub struct EncryptionErrorResponse {
    /// Error message
    #[schema(example = "key not found")]
    pub error: String,
}

// ============ Handlers ============

/// Save workspace key (KEK)
///
/// Saves an encrypted KEK for the authenticated user's device.
/// Requires workspace membership with Read permission.
#[utoipa::path(
    post,
    path = "/api/encryption/workspaces/{workspace_id}/keys",
    request_body = SaveWorkspaceKeyRequest,
    params(
        ("workspace_id" = Uuid, Path, description = "Workspace ID")
    ),
    responses(
        (status = 201, description = "Key saved successfully", body = WorkspaceKeyResponse),
        (status = 400, description = "Invalid request", body = EncryptionErrorResponse),
        (status = 401, description = "Not authenticated", body = EncryptionErrorResponse),
        (status = 403, description = "Permission denied", body = EncryptionErrorResponse),
    ),
    tag = "encryption"
)]
pub async fn save_workspace_key<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>>,
    headers: axum::http::HeaderMap,
    Path(workspace_id): Path<Uuid>,
    Json(request): Json<SaveWorkspaceKeyRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    // Authenticate
    let auth_user = match crate::auth::authenticate(&headers, state.session_repo().as_ref()).await {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    // Verify PoP (Proof of Possession) - required for E2EE key operations
    if let Err(e) = verify_pop(
        &headers,
        auth_user.user_id,
        state.device_repo().as_ref(),
        &state.nonce_cache(),
    )
    .await
    {
        return e.into_response();
    }

    // Decode base64url fields
    let encrypted_kek = match base64_url::decode(&request.encrypted_kek) {
        Ok(k) => k,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(EncryptionErrorResponse {
                    error: "invalid encrypted_kek encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let nonce = match base64_url::decode(&request.nonce) {
        Ok(n) if n.len() == XCHACHA20_NONCE_SIZE => n,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(EncryptionErrorResponse {
                    error: "invalid nonce length: expected 24 bytes".to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(EncryptionErrorResponse {
                    error: "invalid nonce encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let handler = SaveWorkspaceKeyHandler::new(
        state.workspace_key_repo(),
        state.workspace_member_repo(),
        state.workspace_role_repo(),
    );

    let command = SaveWorkspaceKeyCommand {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        user_id: auth_user.user_id,
        device_id: request.device_id.map(DeviceId::from_uuid),
        sender_device_id: request.sender_device_id.map(DeviceId::from_uuid),
        key_version: request.key_version,
        encrypted_kek,
        nonce,
        is_active: request.is_active,
    };

    match handler.handle(command).await {
        Ok(result) => {
            let response = WorkspaceKeyResponse {
                workspace_id: result.key.workspace_id.to_string(),
                user_id: result.key.user_id.to_string(),
                device_id: result.key.device_id.map(|d| d.to_string()),
                sender_device_id: result.key.sender_device_id.map(|d| d.to_string()),
                key_version: result.key.key_version.as_i32(),
                encrypted_kek: base64_url::encode(&result.key.encrypted_kek),
                nonce: base64_url::encode(&result.key.nonce),
                is_active: result.key.is_active,
            };
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(e) => {
            let (status, message) = if e.is_bad_request() {
                (StatusCode::BAD_REQUEST, e.to_string())
            } else if e.is_forbidden() {
                (StatusCode::FORBIDDEN, e.to_string())
            } else {
                tracing::error!("save_workspace_key internal error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            };
            (status, Json(EncryptionErrorResponse { error: message })).into_response()
        }
    }
}

/// Get workspace key (KEK)
///
/// Retrieves the active KEK for the authenticated user's device.
/// Requires workspace membership with Read permission.
#[utoipa::path(
    get,
    path = "/api/encryption/workspaces/{workspace_id}/keys",
    params(
        ("workspace_id" = Uuid, Path, description = "Workspace ID"),
        ("device_id" = Option<Uuid>, Query, description = "Device ID (optional)")
    ),
    responses(
        (status = 200, description = "Key found", body = WorkspaceKeyResponse),
        (status = 401, description = "Not authenticated", body = EncryptionErrorResponse),
        (status = 403, description = "Permission denied", body = EncryptionErrorResponse),
        (status = 404, description = "Key not found", body = EncryptionErrorResponse),
    ),
    tag = "encryption"
)]
pub async fn get_workspace_key<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>>,
    headers: axum::http::HeaderMap,
    Path(workspace_id): Path<Uuid>,
    axum::extract::Query(params): axum::extract::Query<GetWorkspaceKeyParams>,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    // Authenticate
    let auth_user = match crate::auth::authenticate(&headers, state.session_repo().as_ref()).await {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    // Verify PoP (Proof of Possession) - required for E2EE key operations
    if let Err(e) = verify_pop(
        &headers,
        auth_user.user_id,
        state.device_repo().as_ref(),
        &state.nonce_cache(),
    )
    .await
    {
        return e.into_response();
    }

    let handler = GetWorkspaceKeyHandler::new(
        state.workspace_key_repo(),
        state.workspace_member_repo(),
        state.workspace_role_repo(),
    );

    let query = GetWorkspaceKeyQuery {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        user_id: auth_user.user_id,
        device_id: params.device_id.map(DeviceId::from_uuid),
    };

    match handler.handle(query).await {
        Ok(result) => {
            let response = WorkspaceKeyResponse {
                workspace_id: result.key.workspace_id.to_string(),
                user_id: result.key.user_id.to_string(),
                device_id: result.key.device_id.map(|d| d.to_string()),
                sender_device_id: result.key.sender_device_id.map(|d| d.to_string()),
                key_version: result.key.key_version.as_i32(),
                encrypted_kek: base64_url::encode(&result.key.encrypted_kek),
                nonce: base64_url::encode(&result.key.nonce),
                is_active: result.key.is_active,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            let (status, message) = if e.is_not_found() {
                (StatusCode::NOT_FOUND, e.to_string())
            } else if e.is_forbidden() {
                (StatusCode::FORBIDDEN, e.to_string())
            } else {
                tracing::error!("get_workspace_key internal error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            };
            (status, Json(EncryptionErrorResponse { error: message })).into_response()
        }
    }
}

/// Save document key (DEK)
///
/// Saves an encrypted DEK for a document.
/// Requires workspace membership with Write permission.
#[utoipa::path(
    post,
    path = "/api/encryption/documents/{document_id}/keys",
    request_body = SaveDocumentKeyRequest,
    params(
        ("document_id" = Uuid, Path, description = "Document ID")
    ),
    responses(
        (status = 201, description = "Key saved successfully", body = DocumentKeyResponse),
        (status = 400, description = "Invalid request", body = EncryptionErrorResponse),
        (status = 401, description = "Not authenticated", body = EncryptionErrorResponse),
        (status = 403, description = "Permission denied", body = EncryptionErrorResponse),
        (status = 404, description = "Document not found", body = EncryptionErrorResponse),
    ),
    tag = "encryption"
)]
pub async fn save_document_key<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>>,
    headers: axum::http::HeaderMap,
    Path(document_id): Path<Uuid>,
    Json(request): Json<SaveDocumentKeyRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    // Authenticate
    let auth_user = match crate::auth::authenticate(&headers, state.session_repo().as_ref()).await {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    // Verify PoP (Proof of Possession) - required for E2EE key operations
    if let Err(e) = verify_pop(
        &headers,
        auth_user.user_id,
        state.device_repo().as_ref(),
        &state.nonce_cache(),
    )
    .await
    {
        return e.into_response();
    }

    // Decode base64url fields
    let encrypted_dek = match base64_url::decode(&request.encrypted_dek) {
        Ok(k) => k,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(EncryptionErrorResponse {
                    error: "invalid encrypted_dek encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let nonce = match base64_url::decode(&request.nonce) {
        Ok(n) if n.len() == XCHACHA20_NONCE_SIZE => n,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(EncryptionErrorResponse {
                    error: "invalid nonce length: expected 24 bytes".to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(EncryptionErrorResponse {
                    error: "invalid nonce encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let handler = SaveDocumentKeyHandler::new(
        state.document_key_repo(),
        state.document_repo(),
        state.workspace_member_repo(),
        state.workspace_role_repo(),
    );

    let command = SaveDocumentKeyCommand {
        document_id: application::domain::document::DocumentId::from_uuid(document_id),
        user_id: auth_user.user_id,
        key_version: request.key_version,
        encrypted_dek,
        nonce,
        is_active: request.is_active,
    };

    match handler.handle(command).await {
        Ok(result) => {
            let response = DocumentKeyResponse {
                document_id: result.key.document_id.to_string(),
                key_version: result.key.key_version.as_i32(),
                encrypted_dek: base64_url::encode(&result.key.encrypted_dek),
                nonce: base64_url::encode(&result.key.nonce),
                is_active: result.key.is_active,
            };
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(e) => {
            let (status, message) = if e.is_bad_request() {
                (StatusCode::BAD_REQUEST, e.to_string())
            } else if e.is_not_found() {
                (StatusCode::NOT_FOUND, e.to_string())
            } else if e.is_forbidden() {
                (StatusCode::FORBIDDEN, e.to_string())
            } else {
                tracing::error!("save_document_key internal error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            };
            (status, Json(EncryptionErrorResponse { error: message })).into_response()
        }
    }
}

/// Get document key (DEK)
///
/// Retrieves the active DEK for a document.
/// Requires workspace membership with Read permission.
#[utoipa::path(
    get,
    path = "/api/encryption/documents/{document_id}/keys",
    params(
        ("document_id" = Uuid, Path, description = "Document ID")
    ),
    responses(
        (status = 200, description = "Key found", body = DocumentKeyResponse),
        (status = 401, description = "Not authenticated", body = EncryptionErrorResponse),
        (status = 403, description = "Permission denied", body = EncryptionErrorResponse),
        (status = 404, description = "Key not found", body = EncryptionErrorResponse),
    ),
    tag = "encryption"
)]
pub async fn get_document_key<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>>,
    headers: axum::http::HeaderMap,
    Path(document_id): Path<Uuid>,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    // Authenticate
    let auth_user = match crate::auth::authenticate(&headers, state.session_repo().as_ref()).await {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    // Verify PoP (Proof of Possession) - required for E2EE key operations
    if let Err(e) = verify_pop(
        &headers,
        auth_user.user_id,
        state.device_repo().as_ref(),
        &state.nonce_cache(),
    )
    .await
    {
        return e.into_response();
    }

    let handler = GetDocumentKeyHandler::new(
        state.document_key_repo(),
        state.document_repo(),
        state.workspace_member_repo(),
        state.workspace_role_repo(),
    );

    let query = GetDocumentKeyQuery {
        document_id: application::domain::document::DocumentId::from_uuid(document_id),
        user_id: auth_user.user_id,
    };

    match handler.handle(query).await {
        Ok(result) => {
            let response = DocumentKeyResponse {
                document_id: result.key.document_id.to_string(),
                key_version: result.key.key_version.as_i32(),
                encrypted_dek: base64_url::encode(&result.key.encrypted_dek),
                nonce: base64_url::encode(&result.key.nonce),
                is_active: result.key.is_active,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            let (status, message) = if e.is_not_found() {
                (StatusCode::NOT_FOUND, e.to_string())
            } else if e.is_forbidden() {
                (StatusCode::FORBIDDEN, e.to_string())
            } else {
                tracing::error!("get_document_key internal error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            };
            (status, Json(EncryptionErrorResponse { error: message })).into_response()
        }
    }
}
