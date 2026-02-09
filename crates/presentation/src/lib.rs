//! Presentation layer - HTTP interface
//!
//! This layer contains:
//! - HTTP routes: Axum route definitions
//! - WebSocket: Real-time communication (Yjs sync)
//! - Request/Response transformation: JSON to/from DTOs
//! - Authentication middleware: Session validation, authorization

// Allow type_complexity for AppState generics - this is by design for DI
#![allow(clippy::type_complexity)]

// Re-export application for convenience
pub use application;

pub mod auth;
pub mod crypto_validation;
pub mod events;
pub mod middleware;
pub mod rate_limit;
pub mod routes;
pub mod sas;
mod state;

pub use auth::{
    AuthUser, AuthUserFull, PopError, PopVerified, PopVerifiedUser, RecoveryOrPopUser,
    authenticate_with_pop, verify_pop,
};
pub use events::{
    DeviceEvent, DeviceEventBus, DeviceEventPublisher, DeviceEventSubscriber,
    InMemoryDeviceEventBus,
};
pub use middleware::{
    CHALLENGE_TTL_SECS, ChallengeCache, ChallengeError, ChallengeStore, InMemoryChallengeStore,
    InMemoryRecoveryChallengeStore, InMemoryTransferNonceStore, InMemoryTransferStateStore,
    POP_CHALLENGE_HEADER, POP_DEVICE_ID_HEADER, POP_SIGNATURE_HEADER, RecoveryChallengeError,
    RecoveryChallengeStore,
};
pub use state::{AppState, AppStateParams, BoxedError};

use utoipa::OpenApi;

/// OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    info(
        title = "RefMD API",
        version = "0.1.0",
        description = "RefMD E2EE Document Editor API"
    ),
    paths(
        routes::auth::get_salt,
        routes::auth::get_recovery,
        routes::auth::register,
        routes::auth::login,
        routes::auth::logout,
        routes::auth::me,
        routes::auth::create_pop_challenge,
        routes::auth::create_recovery_challenge,
        routes::auth::create_recovery_session,
        routes::workspace::list_workspaces,
        routes::workspace::get_workspace,
        routes::document::list_documents,
        routes::document::create_document,
        routes::document::get_document,
        routes::document::update_document,
        routes::document::delete_document,
        routes::document::archive_document,
        routes::document::unarchive_document,
        routes::document::list_updates,
        routes::document::create_update,
        routes::encryption::save_workspace_key,
        routes::encryption::get_workspace_key,
        routes::encryption::save_document_key,
        routes::encryption::get_document_key,
        routes::encryption::complete_kek_rotation,
        routes::encryption::save_workspace_kek_backup,
        routes::encryption::get_workspace_kek_backup,
        routes::device::create_pending_device,
        routes::device::list_pending_devices,
        routes::device::get_sas,
        routes::device::approve_device,
        routes::device::reject_pending_device,
        routes::device::list_devices,
        routes::device::revoke_device,
        routes::device::distribute_umk,
        routes::device::get_device_umk,
        routes::device::device_events,
        routes::device::pending_device_events,
        routes::trust_transfer::request_nonce,
        routes::trust_transfer::submit_state,
        routes::trust_transfer::retrieve_state,
    ),
    components(
        schemas(
            routes::auth::GetSaltQueryParams,
            routes::auth::GetSaltResponse,
            routes::auth::KdfParamsResponse,
            routes::auth::AuthErrorResponse,
            routes::auth::GetRecoveryQueryParams,
            routes::auth::GetRecoveryResponse,
            routes::auth::RegisterRequest,
            routes::auth::RegisterResponse,
            routes::auth::LoginRequest,
            routes::auth::LoginResponse,
            routes::auth::LogoutResponse,
            routes::auth::MeResponse,
            routes::auth::MeResponseKeys,
            routes::auth::PopChallengeResponse,
            routes::auth::RecoveryChallengeRequest,
            routes::auth::RecoveryChallengeResponse,
            routes::auth::RecoverySessionRequest,
            routes::auth::RecoverySessionResponse,
            routes::workspace::WorkspaceResponse,
            routes::workspace::MembershipResponse,
            routes::workspace::RoleResponse,
            routes::workspace::WorkspaceWithMembershipResponse,
            routes::workspace::ListWorkspacesResponse,
            routes::workspace::WorkspaceErrorResponse,
            routes::document::DocumentResponse,
            routes::document::CreateDocumentRequest,
            routes::document::UpdateDocumentRequest,
            routes::document::ListDocumentsParams,
            routes::document::ListDocumentsResponse,
            routes::document::DocumentErrorResponse,
            routes::document::DocumentUpdateResponse,
            routes::document::ListDocumentUpdatesResponse,
            routes::document::ListDocumentUpdatesParams,
            routes::document::CreateDocumentUpdateRequest,
            routes::document::CreateDocumentUpdateResponse,
            routes::encryption::SaveWorkspaceKeyRequest,
            routes::encryption::WorkspaceKeyResponse,
            routes::encryption::GetWorkspaceKeyParams,
            routes::encryption::SaveDocumentKeyRequest,
            routes::encryption::DocumentKeyResponse,
            routes::encryption::EncryptionErrorResponse,
            routes::encryption::CompleteKekRotationRequest,
            routes::encryption::CompleteKekRotationResponse,
            routes::encryption::SaveWorkspaceKekBackupRequest,
            routes::encryption::WorkspaceKekBackupResponse,
            routes::device::CreatePendingDeviceRequest,
            routes::device::CreatePendingDeviceResponse,
            routes::device::GetSasResponse,
            routes::device::ApproveDeviceRequest,
            routes::device::ApproveDeviceResponse,
            routes::device::RejectPendingDeviceResponse,
            routes::device::PendingDeviceResponse,
            routes::device::ListPendingDevicesResponse,
            routes::device::DeviceResponse,
            routes::device::ListDevicesResponse,
            routes::device::DistributeUmkRequest,
            routes::device::DistributeUmkResponse,
            routes::device::GetDeviceUmkResponse,
            routes::device::DeviceErrorResponse,
            routes::device::RevokeDeviceRequest,
            routes::device::RevokeDeviceResponse,
            routes::trust_transfer::RequestNonceRequest,
            routes::trust_transfer::RequestNonceResponse,
            routes::trust_transfer::RequestNonceErrorResponse,
            routes::trust_transfer::SubmitStateRequest,
            routes::trust_transfer::SubmitStateErrorResponse,
            routes::trust_transfer::RetrieveStateResponse,
            routes::trust_transfer::RetrieveStateErrorResponse,
        )
    ),
    tags(
        (name = "auth", description = "Authentication endpoints"),
        (name = "workspace", description = "Workspace management endpoints"),
        (name = "document", description = "Document management endpoints"),
        (name = "encryption", description = "Encryption key management endpoints"),
        (name = "device", description = "Device management endpoints"),
        (name = "trust-transfer", description = "Trust state transfer endpoints"),
    )
)]
pub struct ApiDoc;
