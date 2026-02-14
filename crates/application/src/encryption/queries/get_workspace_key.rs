//! Get workspace key query
//!
//! Retrieves the active KEK for a user's device in a workspace.
//! Requires workspace membership (Read permission minimum).

use crate::dto::WorkspaceEncryptedKeyDto;
use domain::encryption::{
    DeviceId, DeviceRepository, WorkspaceEncryptedKeyRepository,
};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository,
};
use std::sync::Arc;

use crate::util::workspace_access::{WorkspaceAccessError, check_workspace_permission};
use thiserror::Error;

/// Get workspace key query
#[derive(Debug)]
pub struct GetWorkspaceKeyQuery {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub device_id: DeviceId,
    /// The device ID verified by PoP — must match `device_id`
    pub pop_verified_device_id: DeviceId,
}

/// Get workspace key result
#[derive(Debug)]
pub struct GetWorkspaceKeyResult {
    pub key: WorkspaceEncryptedKeyDto,
    /// Sender device's ECDH public key (for ECDH decryption)
    pub sender_ecdh_public_key: Vec<u8>,
    /// Sender device's signing public key (for TOFU verification)
    pub sender_signing_public_key: Vec<u8>,
}

/// Get workspace key error
#[derive(Debug, Error)]
pub enum GetWorkspaceKeyError<
    WKR: std::error::Error,
    MR: std::error::Error,
    RR: std::error::Error,
    DR: std::error::Error,
> {
    #[error("device_id does not match PoP-verified device")]
    DeviceMismatch,

    #[error("workspace key not found")]
    KeyNotFound,

    #[error("sender device not found")]
    SenderDeviceNotFound,

    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR>),

    #[error("workspace key repository error: {0}")]
    WorkspaceKeyRepository(WKR),

    #[error("device repository error: {0}")]
    DeviceRepository(DR),
}

impl<WKR: std::error::Error, MR: std::error::Error, RR: std::error::Error, DR: std::error::Error>
    crate::types::AppError for GetWorkspaceKeyError<WKR, MR, RR, DR>
{
    fn is_not_found(&self) -> bool {
        matches!(
            self,
            GetWorkspaceKeyError::KeyNotFound
                | GetWorkspaceKeyError::SenderDeviceNotFound
                | GetWorkspaceKeyError::WorkspaceAccess(WorkspaceAccessError::NotMember)
        )
    }

    fn is_access_denied(&self) -> bool {
        matches!(
            self,
            GetWorkspaceKeyError::DeviceMismatch
                | GetWorkspaceKeyError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied)
        )
    }
}

/// Get workspace key handler
pub struct GetWorkspaceKeyHandler<WKR: ?Sized, MR: ?Sized, RR: ?Sized, DR: ?Sized> {
    workspace_key_repo: Arc<WKR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    device_repo: Arc<DR>,
}

impl<WKR, MR, RR, DR> GetWorkspaceKeyHandler<WKR, MR, RR, DR>
where
    WKR: WorkspaceEncryptedKeyRepository + ?Sized,
    MR: WorkspaceMemberRepository + ?Sized,
    RR: WorkspaceRoleRepository + ?Sized,
    DR: DeviceRepository + ?Sized,
{
    pub fn new(
        workspace_key_repo: Arc<WKR>,
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
        device_repo: Arc<DR>,
    ) -> Self {
        Self {
            workspace_key_repo,
            member_repo,
            role_repo,
            device_repo,
        }
    }

    pub async fn handle(
        &self,
        query: GetWorkspaceKeyQuery,
    ) -> Result<
        GetWorkspaceKeyResult,
        GetWorkspaceKeyError<WKR::Error, MR::Error, RR::Error, DR::Error>,
    > {
        // 1. Verify device_id matches PoP-verified device
        if query.device_id != query.pop_verified_device_id {
            return Err(GetWorkspaceKeyError::DeviceMismatch);
        }

        // 2. Check membership and Read permission
        check_workspace_permission(
            &self.member_repo,
            &self.role_repo,
            query.workspace_id,
            query.user_id,
            WorkspacePermission::Read,
        )
        .await
        .map_err(GetWorkspaceKeyError::WorkspaceAccess)?;

        // 3. Get active key for device
        let key = self
            .workspace_key_repo
            .find_active_by_device(query.workspace_id, query.user_id, query.device_id)
            .await
            .map_err(GetWorkspaceKeyError::WorkspaceKeyRepository)?
            .ok_or(GetWorkspaceKeyError::KeyNotFound)?;

        // 4. Get sender device's public keys (ECDH for decryption, signing for TOFU)
        let sender_device = self
            .device_repo
            .find_by_id(key.sender_device_id)
            .await
            .map_err(GetWorkspaceKeyError::DeviceRepository)?
            .ok_or(GetWorkspaceKeyError::SenderDeviceNotFound)?;
        let sender_ecdh_public_key = sender_device.ecdh_public_key.clone();
        let sender_signing_public_key = sender_device.signing_public_key;

        Ok(GetWorkspaceKeyResult {
            key: key.into(),
            sender_ecdh_public_key,
            sender_signing_public_key,
        })
    }
}
