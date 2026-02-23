//! Presentation layer - HTTP interface
//!
//! This layer contains:
//! - HTTP routes: Axum route definitions
//! - WebSocket: Real-time communication (Yjs sync)
//! - Request/Response transformation: JSON to/from DTOs
//! - Authentication middleware: Session validation, authorization
//!
//! # Architecture boundary
//!
//! This layer depends on `application` only (not `domain` directly).
//! Domain types are accessed via `application::types` (IDs, traits)
//! and `application::dto` (data transfer objects).

pub mod auth;
pub mod client_ip;
pub mod crypto_validation;
pub mod events;
pub mod rate_limit;
pub mod routes;
mod state;

pub use auth::{AuthUser, AuthError, PopVerifiedUser, RecoveryOrPopUser};
pub use events::{
    DeviceEvent, DeviceEventBus, DeviceEventPublisher, DeviceEventSubscriber,
};
pub use auth::{POP_CHALLENGE_HEADER, POP_DEVICE_ID_HEADER, POP_SIGNATURE_HEADER};
pub use state::{
    AppState, AppStateParams, AuthSubState, DeviceSubState, DocumentSubState, EncryptionSubState,
    TrustTransferSubState, WorkspaceSubState,
};

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
        routes::workspace::crud::create_workspace,
        routes::workspace::crud::update_workspace,
        routes::workspace::crud::delete_workspace,
        routes::workspace::members::list_members,
        routes::workspace::members::change_member_role,
        routes::workspace::members::remove_member,
        routes::workspace::roles::list_roles,
        routes::workspace::roles::create_role,
        routes::workspace::roles::update_role,
        routes::workspace::roles::delete_role,
        routes::workspace::invitations::list_invitations,
        routes::workspace::invitations::create_invitation,
        routes::workspace::invitations::revoke_invitation,
        routes::workspace::events::workspace_events,
        routes::invitation::accept_invitation,
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
            routes::workspace::crud::CreateWorkspaceRequest,
            routes::workspace::crud::UpdateWorkspaceRequest,
            routes::workspace::members::MemberDetailResponse,
            routes::workspace::members::ListMembersResponse,
            routes::workspace::members::ChangeMemberRoleRequest,
            routes::workspace::roles::RoleDetailResponse,
            routes::workspace::roles::ListRolesResponse,
            routes::workspace::roles::CreateRoleRequest,
            routes::workspace::roles::UpdateRoleRequest,
            routes::workspace::roles::PermissionOverride,
            routes::workspace::invitations::CreateInvitationResponse,
            routes::workspace::invitations::InvitationListItem,
            routes::workspace::invitations::ListInvitationsResponse,
            routes::workspace::invitations::CreateInvitationRequest,
            routes::invitation::AcceptInvitationRequest,
            routes::invitation::AcceptInvitationResponse,
            routes::invitation::InvitationErrorResponse,
            routes::trust_transfer::RequestNonceRequest,
            routes::trust_transfer::RequestNonceResponse,
            routes::trust_transfer::TrustTransferErrorResponse,
            routes::trust_transfer::SubmitStateRequest,
            routes::trust_transfer::RetrieveStateResponse,
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
