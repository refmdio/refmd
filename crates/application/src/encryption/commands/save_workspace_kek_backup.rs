//! Save workspace KEK backup command
//!
//! Saves a KEK encrypted with UMK for recovery purposes.
//! Requires workspace membership (Read permission minimum).

use domain::encryption::{
    KeyVersion, NewWorkspaceKekBackupParams, WorkspaceKekBackup, WorkspaceKekBackupRepository,
    WorkspaceEncryptedKeyRepository,
};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository,
    can_perform,
};
use std::sync::Arc;
use thiserror::Error;

/// XChaCha20-Poly1305 nonce size
const XCHACHA20_NONCE_SIZE: usize = 24;

/// Save workspace KEK backup command
#[derive(Debug)]
pub struct SaveWorkspaceKekBackupCommand {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub key_version: u32,
    pub encrypted_kek: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Save workspace KEK backup result
#[derive(Debug)]
pub struct SaveWorkspaceKekBackupResult {
    pub backup: WorkspaceKekBackup,
}

/// Save workspace KEK backup error
#[derive(Debug, Error)]
pub enum SaveWorkspaceKekBackupError<BR: std::error::Error, MR: std::error::Error, RR: std::error::Error, WKR: std::error::Error> {
    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("permission denied: cannot access this workspace")]
    PermissionDenied,

    #[error("invalid key version: must be between 1 and {}", i32::MAX)]
    InvalidKeyVersion,

    #[error("key version mismatch: provided {provided} does not match active KEK version {active}")]
    KeyVersionMismatch { provided: i32, active: i32 },

    #[error("no active KEK found for this workspace")]
    NoActiveKek,

    #[error("invalid nonce length: expected {XCHACHA20_NONCE_SIZE} bytes")]
    InvalidNonceLength,

    #[error("backup repository error: {0}")]
    BackupRepository(BR),

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),

    #[error("workspace key repository error: {0}")]
    WorkspaceKeyRepository(WKR),
}

impl<BR: std::error::Error, MR: std::error::Error, RR: std::error::Error, WKR: std::error::Error>
    SaveWorkspaceKekBackupError<BR, MR, RR, WKR>
{
    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            SaveWorkspaceKekBackupError::NotMember | SaveWorkspaceKekBackupError::PermissionDenied
        )
    }

    pub fn is_bad_request(&self) -> bool {
        matches!(
            self,
            SaveWorkspaceKekBackupError::InvalidKeyVersion
                | SaveWorkspaceKekBackupError::InvalidNonceLength
                | SaveWorkspaceKekBackupError::KeyVersionMismatch { .. }
                | SaveWorkspaceKekBackupError::NoActiveKek
        )
    }
}

/// Save workspace KEK backup handler
pub struct SaveWorkspaceKekBackupHandler<BR: ?Sized, MR, RR, WKR> {
    backup_repo: Arc<BR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    workspace_key_repo: Arc<WKR>,
}

impl<BR, MR, RR, WKR> SaveWorkspaceKekBackupHandler<BR, MR, RR, WKR>
where
    BR: WorkspaceKekBackupRepository + ?Sized,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    WKR: WorkspaceEncryptedKeyRepository,
{
    pub fn new(
        backup_repo: Arc<BR>,
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
        workspace_key_repo: Arc<WKR>,
    ) -> Self {
        Self {
            backup_repo,
            member_repo,
            role_repo,
            workspace_key_repo,
        }
    }

    pub async fn handle(
        &self,
        command: SaveWorkspaceKekBackupCommand,
    ) -> Result<
        SaveWorkspaceKekBackupResult,
        SaveWorkspaceKekBackupError<BR::Error, MR::Error, RR::Error, WKR::Error>,
    > {
        // 1. Validate nonce length
        if command.nonce.len() != XCHACHA20_NONCE_SIZE {
            return Err(SaveWorkspaceKekBackupError::InvalidNonceLength);
        }

        // 2. Validate key version
        if command.key_version == 0 || command.key_version > i32::MAX as u32 {
            return Err(SaveWorkspaceKekBackupError::InvalidKeyVersion);
        }

        // 3. Check membership
        let member = self
            .member_repo
            .find_by_workspace_and_user(command.workspace_id, command.user_id)
            .await
            .map_err(SaveWorkspaceKekBackupError::MemberRepository)?
            .ok_or(SaveWorkspaceKekBackupError::NotMember)?;

        // 4. Get role and check Read permission
        let role = self
            .role_repo
            .find_by_id(member.role_id)
            .await
            .map_err(SaveWorkspaceKekBackupError::RoleRepository)?
            .ok_or(SaveWorkspaceKekBackupError::NotMember)?;

        if !can_perform(role.base_role, WorkspacePermission::Read) {
            return Err(SaveWorkspaceKekBackupError::PermissionDenied);
        }

        // 5. Validate key_version matches the requesting user's active KEK version
        // Uses user-scoped keys (not workspace-global) to prevent DoS via other users
        // injecting high version numbers
        let existing_keys = self
            .workspace_key_repo
            .find_by_workspace_id(command.workspace_id)
            .await
            .map_err(SaveWorkspaceKekBackupError::WorkspaceKeyRepository)?;

        let user_active_version = existing_keys
            .iter()
            .filter(|k| k.is_active && k.user_id == command.user_id)
            .map(|k| k.key_version.as_i32())
            .max();

        match user_active_version {
            Some(active_v) => {
                if command.key_version as i32 != active_v {
                    return Err(SaveWorkspaceKekBackupError::KeyVersionMismatch {
                        provided: command.key_version as i32,
                        active: active_v,
                    });
                }
            }
            None => {
                // No active KEK for this user — this backup would be orphaned
                return Err(SaveWorkspaceKekBackupError::NoActiveKek);
            }
        }

        // 6. Create and save backup
        let backup = WorkspaceKekBackup::new(NewWorkspaceKekBackupParams {
            workspace_id: command.workspace_id,
            user_id: command.user_id,
            key_version: KeyVersion::new(command.key_version as i32)
                .map_err(|_| SaveWorkspaceKekBackupError::InvalidKeyVersion)?,
            encrypted_kek: command.encrypted_kek,
            nonce: command.nonce,
            is_active: true,
        });

        self.backup_repo
            .save(&backup)
            .await
            .map_err(SaveWorkspaceKekBackupError::BackupRepository)?;

        Ok(SaveWorkspaceKekBackupResult { backup })
    }
}
