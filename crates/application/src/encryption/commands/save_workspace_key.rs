//! Save workspace key command
//!
//! Saves an encrypted KEK for a user's device in a workspace.
//! Requires workspace membership (Read permission minimum).

use domain::encryption::{
    DeviceId, DeviceRepository, KeyVersion, NewWorkspaceKeyParams, WorkspaceEncryptedKey,
    WorkspaceEncryptedKeyRepository,
};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspacePermission, WorkspaceRepository,
    WorkspaceRoleRepository, can_perform,
};
use std::sync::Arc;
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
    /// Encrypted KEK
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
pub enum SaveWorkspaceKeyError<
    WKR: std::error::Error,
    MR: std::error::Error,
    RR: std::error::Error,
    DR: std::error::Error,
    WR: std::error::Error,
> {
    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("permission denied: cannot access this workspace")]
    PermissionDenied,

    #[error("invalid key version: must be between 1 and {}", i32::MAX)]
    InvalidKeyVersion,

    #[error("key version too old: minimum required is {min_version}, got {provided_version}")]
    KeyVersionTooOld {
        min_version: i32,
        provided_version: i32,
    },

    #[error("workspace not found")]
    WorkspaceNotFound,

    #[error("device not found")]
    DeviceNotFound,

    #[error("device does not belong to user")]
    DeviceNotOwned,

    #[error("KEK already exists for this workspace: use backup restore or device distribution instead of creating a new key")]
    KeyAlreadyExists,

    #[error("workspace key repository error: {0}")]
    WorkspaceKeyRepository(WKR),

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),

    #[error("device repository error: {0}")]
    DeviceRepository(DR),

    #[error("workspace repository error: {0}")]
    WorkspaceRepository(WR),
}

impl<
    WKR: std::error::Error,
    MR: std::error::Error,
    RR: std::error::Error,
    DR: std::error::Error,
    WR: std::error::Error,
> SaveWorkspaceKeyError<WKR, MR, RR, DR, WR>
{
    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            SaveWorkspaceKeyError::NotMember
                | SaveWorkspaceKeyError::PermissionDenied
                | SaveWorkspaceKeyError::DeviceNotOwned
        )
    }

    pub fn is_conflict(&self) -> bool {
        matches!(self, SaveWorkspaceKeyError::KeyAlreadyExists)
    }

    pub fn is_bad_request(&self) -> bool {
        matches!(
            self,
            SaveWorkspaceKeyError::InvalidKeyVersion
                | SaveWorkspaceKeyError::KeyVersionTooOld { .. }
        )
    }

    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            SaveWorkspaceKeyError::DeviceNotFound | SaveWorkspaceKeyError::WorkspaceNotFound
        )
    }
}

/// Save workspace key handler
pub struct SaveWorkspaceKeyHandler<WKR, MR, RR, DR, WR> {
    workspace_key_repo: Arc<WKR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    device_repo: Arc<DR>,
    workspace_repo: Arc<WR>,
}

impl<WKR, MR, RR, DR, WR> SaveWorkspaceKeyHandler<WKR, MR, RR, DR, WR>
where
    WKR: WorkspaceEncryptedKeyRepository,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    DR: DeviceRepository,
    WR: WorkspaceRepository,
{
    pub fn new(
        workspace_key_repo: Arc<WKR>,
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
        device_repo: Arc<DR>,
        workspace_repo: Arc<WR>,
    ) -> Self {
        Self {
            workspace_key_repo,
            member_repo,
            role_repo,
            device_repo,
            workspace_repo,
        }
    }

    pub async fn handle(
        &self,
        command: SaveWorkspaceKeyCommand,
    ) -> Result<
        SaveWorkspaceKeyResult,
        SaveWorkspaceKeyError<WKR::Error, MR::Error, RR::Error, DR::Error, WR::Error>,
    > {
        // 1. Get workspace to check min_kek_version
        let workspace = self
            .workspace_repo
            .find_by_id(command.workspace_id)
            .await
            .map_err(SaveWorkspaceKeyError::WorkspaceRepository)?
            .ok_or(SaveWorkspaceKeyError::WorkspaceNotFound)?;

        // 2. Check membership
        let member = self
            .member_repo
            .find_by_workspace_and_user(command.workspace_id, command.user_id)
            .await
            .map_err(SaveWorkspaceKeyError::MemberRepository)?
            .ok_or(SaveWorkspaceKeyError::NotMember)?;

        // 3. Get role and check Read permission (minimum required to access workspace keys)
        let role = self
            .role_repo
            .find_by_id(member.role_id)
            .await
            .map_err(SaveWorkspaceKeyError::RoleRepository)?
            .ok_or(SaveWorkspaceKeyError::NotMember)?;

        if !can_perform(role.base_role, WorkspacePermission::Read) {
            return Err(SaveWorkspaceKeyError::PermissionDenied);
        }

        // 4. Validate device ownership
        let device = self
            .device_repo
            .find_by_id(command.device_id)
            .await
            .map_err(SaveWorkspaceKeyError::DeviceRepository)?
            .ok_or(SaveWorkspaceKeyError::DeviceNotFound)?;

        if device.user_id != command.user_id {
            return Err(SaveWorkspaceKeyError::DeviceNotOwned);
        }

        // Validate sender_device_id ownership
        let sender_device = self
            .device_repo
            .find_by_id(command.sender_device_id)
            .await
            .map_err(SaveWorkspaceKeyError::DeviceRepository)?
            .ok_or(SaveWorkspaceKeyError::DeviceNotFound)?;

        if sender_device.user_id != command.user_id {
            return Err(SaveWorkspaceKeyError::DeviceNotOwned);
        }

        // 5. Validate and create key version
        let key_version = if let Some(v) = command.key_version {
            // Validate key version is positive and within i32 range
            if v == 0 || v > i32::MAX as u32 {
                return Err(SaveWorkspaceKeyError::InvalidKeyVersion);
            }
            KeyVersion::new(v as i32)
        } else {
            // Auto-determine: max(existing) + 1, at least min_kek_version
            let existing_keys = self
                .workspace_key_repo
                .find_by_workspace_id(command.workspace_id)
                .await
                .map_err(SaveWorkspaceKeyError::WorkspaceKeyRepository)?;

            // Guard: if keys already exist for this workspace, reject auto-version
            // (prevents key fork — new KEK creation is only valid for brand-new workspaces)
            if !existing_keys.is_empty() {
                return Err(SaveWorkspaceKeyError::KeyAlreadyExists);
            }

            let max_version = existing_keys
                .iter()
                .map(|k| k.key_version.as_i32())
                .max()
                .unwrap_or(0);
            let next = std::cmp::max(max_version + 1, workspace.min_kek_version);
            KeyVersion::new(next)
        };

        // 6. Check KEK version meets minimum requirement (after key rotation)
        if key_version.as_i32() < workspace.min_kek_version {
            return Err(SaveWorkspaceKeyError::KeyVersionTooOld {
                min_version: workspace.min_kek_version,
                provided_version: key_version.as_i32(),
            });
        }

        // 7. Create and save key
        let key = WorkspaceEncryptedKey::new(NewWorkspaceKeyParams {
            workspace_id: command.workspace_id,
            user_id: command.user_id,
            device_id: command.device_id,
            sender_device_id: command.sender_device_id,
            key_version,
            encrypted_kek: command.encrypted_kek,
            nonce: command.nonce,
            is_active: command.is_active,
        });

        // 8. Save key
        self.workspace_key_repo
            .save(&key)
            .await
            .map_err(SaveWorkspaceKeyError::WorkspaceKeyRepository)?;

        Ok(SaveWorkspaceKeyResult { key })
    }
}
