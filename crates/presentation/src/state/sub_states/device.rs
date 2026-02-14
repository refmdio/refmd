use std::sync::Arc;

use super::*;

/// Sub-state for device-related routes
#[derive(Clone)]
pub struct DeviceSubState {
    pub device_repo: DynDeviceRepository,
    pub pending_device_repo: DynPendingDeviceRepository,
    pub device_encrypted_umk_repo: DynDeviceEncryptedUMKRepository,
    pub device_revocation_event_repo: DynDeviceRevocationEventRepository,
    pub user_identity_public_key_repo: DynUserIdentityPublicKeyRepository,
    pub workspace_member_repo: DynWorkspaceMemberRepository,
    pub workspace_repo: DynWorkspaceRepository,
    pub document_repo: DynDocumentRepository,
    pub document_key_repo: DynDocumentEncryptedKeyRepository,
    pub device_event_bus: DynDeviceEventBus,
    pub challenge_store: DynChallengeStore,
}

impl_from_ref!(DeviceSubState {
    device_repo, pending_device_repo, device_encrypted_umk_repo,
    device_revocation_event_repo, user_identity_public_key_repo,
    workspace_member_repo, workspace_repo, document_repo,
    document_key_repo, device_event_bus, challenge_store,
});
