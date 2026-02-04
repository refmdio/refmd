//! Get workspace key query
//!
//! Retrieves the active KEK for a user's device in a workspace.
//! Requires workspace membership (Read permission minimum).

use domain::encryption::{DeviceId, DeviceRepository, WorkspaceEncryptedKey, WorkspaceEncryptedKeyRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository,
    can_perform,
};
use std::sync::Arc;
use thiserror::Error;

/// Get workspace key query
#[derive(Debug)]
pub struct GetWorkspaceKeyQuery {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub device_id: DeviceId,
}

/// Get workspace key result
#[derive(Debug)]
pub struct GetWorkspaceKeyResult {
    pub key: WorkspaceEncryptedKey,
    /// Sender device's ECDH public key (for ECDH decryption)
    pub sender_ecdh_public_key: Option<Vec<u8>>,
}

/// Get workspace key error
#[derive(Debug, Error)]
pub enum GetWorkspaceKeyError<WKR: std::error::Error, MR: std::error::Error, RR: std::error::Error, DR: std::error::Error>
{
    #[error("workspace key not found")]
    KeyNotFound,

    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("permission denied: cannot access this workspace")]
    PermissionDenied,

    #[error("workspace key repository error: {0}")]
    WorkspaceKeyRepository(WKR),

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),

    #[error("device repository error: {0}")]
    DeviceRepository(DR),
}

impl<WKR: std::error::Error, MR: std::error::Error, RR: std::error::Error, DR: std::error::Error>
    GetWorkspaceKeyError<WKR, MR, RR, DR>
{
    pub fn is_not_found(&self) -> bool {
        matches!(self, GetWorkspaceKeyError::KeyNotFound)
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            GetWorkspaceKeyError::NotMember | GetWorkspaceKeyError::PermissionDenied
        )
    }
}

/// Get workspace key handler
pub struct GetWorkspaceKeyHandler<WKR, MR, RR, DR> {
    workspace_key_repo: Arc<WKR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    device_repo: Arc<DR>,
}

impl<WKR, MR, RR, DR> GetWorkspaceKeyHandler<WKR, MR, RR, DR>
where
    WKR: WorkspaceEncryptedKeyRepository,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    DR: DeviceRepository,
{
    pub fn new(workspace_key_repo: Arc<WKR>, member_repo: Arc<MR>, role_repo: Arc<RR>, device_repo: Arc<DR>) -> Self {
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
    ) -> Result<GetWorkspaceKeyResult, GetWorkspaceKeyError<WKR::Error, MR::Error, RR::Error, DR::Error>> {
        // 1. Check membership
        let member = self
            .member_repo
            .find_by_workspace_and_user(query.workspace_id, query.user_id)
            .await
            .map_err(GetWorkspaceKeyError::MemberRepository)?
            .ok_or(GetWorkspaceKeyError::NotMember)?;

        // 2. Get role and check Read permission
        let role = self
            .role_repo
            .find_by_id(member.role_id)
            .await
            .map_err(GetWorkspaceKeyError::RoleRepository)?
            .ok_or(GetWorkspaceKeyError::NotMember)?;

        if !can_perform(role.base_role, WorkspacePermission::Read) {
            return Err(GetWorkspaceKeyError::PermissionDenied);
        }

        // 3. Get active key for device
        let key = self
            .workspace_key_repo
            .find_active_by_device(query.workspace_id, query.user_id, query.device_id)
            .await
            .map_err(GetWorkspaceKeyError::WorkspaceKeyRepository)?
            .ok_or(GetWorkspaceKeyError::KeyNotFound)?;

        // 4. Get sender device's ECDH public key
        let sender_ecdh_public_key = {
            let sender_device = self
                .device_repo
                .find_by_id(key.sender_device_id)
                .await
                .map_err(GetWorkspaceKeyError::DeviceRepository)?;
            sender_device.map(|d| d.ecdh_public_key)
        };

        Ok(GetWorkspaceKeyResult { key, sender_ecdh_public_key })
    }
}
