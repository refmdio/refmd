//! Save workspace key command
//!
//! Saves an encrypted KEK for a user's device in a workspace.
//! Requires workspace membership (Read permission minimum).
//!
//! Note: Device ownership validation is deferred to Phase 2 (multi-device support).
//! Currently, the client provides device_id and sender_device_id without server-side
//! validation of ownership. This will be addressed when Device management is implemented.

use std::sync::Arc;
use domain::encryption::{DeviceId, KeyVersion, WorkspaceEncryptedKey, WorkspaceEncryptedKeyRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository,
    can_perform,
};
use thiserror::Error;

/// Save workspace key command
#[derive(Debug)]
pub struct SaveWorkspaceKeyCommand {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub sender_device_id: DeviceId,
    /// Key version (default: 1 for new keys)
    pub key_version: Option<u32>,
    /// Encrypted KEK (encrypted with device's ECDH public key)
    pub encrypted_kek: Vec<u8>,
    /// Encryption nonce
    pub nonce: Vec<u8>,
    /// Whether this is the active key version
    pub is_active: bool,
}

/// Save workspace key result
#[derive(Debug)]
pub struct SaveWorkspaceKeyResult {
    pub key: WorkspaceEncryptedKey,
}

/// Save workspace key error
#[derive(Debug, Error)]
pub enum SaveWorkspaceKeyError<WKR: std::error::Error, MR: std::error::Error, RR: std::error::Error>
{
    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("permission denied: cannot access this workspace")]
    PermissionDenied,

    #[error("invalid key version: must be between 1 and {}", i32::MAX)]
    InvalidKeyVersion,

    #[error("workspace key repository error: {0}")]
    WorkspaceKeyRepository(WKR),

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),
}

impl<WKR: std::error::Error, MR: std::error::Error, RR: std::error::Error>
    SaveWorkspaceKeyError<WKR, MR, RR>
{
    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            SaveWorkspaceKeyError::NotMember | SaveWorkspaceKeyError::PermissionDenied
        )
    }

    pub fn is_bad_request(&self) -> bool {
        matches!(self, SaveWorkspaceKeyError::InvalidKeyVersion)
    }
}

/// Save workspace key handler
pub struct SaveWorkspaceKeyHandler<WKR, MR, RR> {
    workspace_key_repo: Arc<WKR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<WKR, MR, RR> SaveWorkspaceKeyHandler<WKR, MR, RR>
where
    WKR: WorkspaceEncryptedKeyRepository,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
{
    pub fn new(
        workspace_key_repo: Arc<WKR>,
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
    ) -> Self {
        Self {
            workspace_key_repo,
            member_repo,
            role_repo,
        }
    }

    pub async fn handle(
        &self,
        command: SaveWorkspaceKeyCommand,
    ) -> Result<SaveWorkspaceKeyResult, SaveWorkspaceKeyError<WKR::Error, MR::Error, RR::Error>>
    {
        // 1. Check membership
        let member = self
            .member_repo
            .find_by_workspace_and_user(command.workspace_id, command.user_id)
            .await
            .map_err(SaveWorkspaceKeyError::MemberRepository)?
            .ok_or(SaveWorkspaceKeyError::NotMember)?;

        // 2. Get role and check Read permission (minimum required to access workspace keys)
        let role = self
            .role_repo
            .find_by_id(member.role_id)
            .await
            .map_err(SaveWorkspaceKeyError::RoleRepository)?
            .ok_or(SaveWorkspaceKeyError::NotMember)?;

        if !can_perform(role.base_role, WorkspacePermission::Read) {
            return Err(SaveWorkspaceKeyError::PermissionDenied);
        }

        // 3. Validate and create key version
        let key_version = if let Some(v) = command.key_version {
            // Validate key version is positive and within i32 range
            if v == 0 || v > i32::MAX as u32 {
                return Err(SaveWorkspaceKeyError::InvalidKeyVersion);
            }
            KeyVersion::new(v as i32)
        } else {
            KeyVersion::initial()
        };

        let key = WorkspaceEncryptedKey::new(
            command.workspace_id,
            command.user_id,
            command.device_id,
            command.sender_device_id,
            key_version,
            command.encrypted_kek,
            command.nonce,
            command.is_active,
        );

        // 4. Save key
        self.workspace_key_repo
            .save(&key)
            .await
            .map_err(SaveWorkspaceKeyError::WorkspaceKeyRepository)?;

        Ok(SaveWorkspaceKeyResult { key })
    }
}
