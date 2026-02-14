//! Save workspace key command
//!
//! Saves an encrypted KEK for a user's device in a workspace.
//! Requires workspace membership (Read permission minimum).

use crate::dto::WorkspaceEncryptedKeyDto;
use domain::encryption::{
    DeviceId, DeviceRepository, NewWorkspaceKeyParams, WorkspaceEncryptedKey,
    WorkspaceEncryptedKeyRepository,
};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspacePermission, WorkspaceRepository,
    WorkspaceRoleRepository,
};
use std::sync::Arc;

use crate::util::device_ownership::verify_pop_sender_and_devices;
use crate::util::workspace_access::{WorkspaceAccessError, check_workspace_permission};
use thiserror::Error;

/// Save workspace key command
#[derive(Debug)]
pub struct SaveWorkspaceKeyCommand {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub sender_device_id: DeviceId,
    /// PoP-authenticated device ID — must match `sender_device_id`
    pub authenticated_device_id: DeviceId,
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
    pub key: WorkspaceEncryptedKeyDto,
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
    #[error("sender_device_id does not match authenticated device")]
    SenderDeviceMismatch,

    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR>),

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

    #[error("device has been revoked")]
    DeviceRevoked,

    #[error("KEK already exists for this workspace: use backup restore or device distribution instead of creating a new key")]
    KeyAlreadyExists,

    #[error("workspace key repository error: {0}")]
    WorkspaceKeyRepository(WKR),

    #[error("device repository error: {0}")]
    DeviceRepository(DR),

    #[error("workspace repository error: {0}")]
    WorkspaceRepository(WR),
}

crate::types::impl_app_error!(
    [WKR: std::error::Error, MR: std::error::Error, RR: std::error::Error, DR: std::error::Error, WR: std::error::Error]
    SaveWorkspaceKeyError<WKR, MR, RR, DR, WR>,
    not_found: [
        SaveWorkspaceKeyError::DeviceNotFound,
        SaveWorkspaceKeyError::WorkspaceNotFound,
        SaveWorkspaceKeyError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        SaveWorkspaceKeyError::SenderDeviceMismatch,
        SaveWorkspaceKeyError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
        SaveWorkspaceKeyError::DeviceNotOwned,
    ],
    invalid_input: [
        SaveWorkspaceKeyError::InvalidKeyVersion,
        SaveWorkspaceKeyError::KeyVersionTooOld { .. },
        SaveWorkspaceKeyError::DeviceRevoked,
    ],
    conflict: [SaveWorkspaceKeyError::KeyAlreadyExists],
);

/// Save workspace key handler
pub struct SaveWorkspaceKeyHandler<WKR: ?Sized, MR: ?Sized, RR: ?Sized, DR: ?Sized, WR: ?Sized> {
    workspace_key_repo: Arc<WKR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    device_repo: Arc<DR>,
    workspace_repo: Arc<WR>,
}

impl<WKR, MR, RR, DR, WR> SaveWorkspaceKeyHandler<WKR, MR, RR, DR, WR>
where
    WKR: WorkspaceEncryptedKeyRepository + ?Sized,
    MR: WorkspaceMemberRepository + ?Sized,
    RR: WorkspaceRoleRepository + ?Sized,
    DR: DeviceRepository + ?Sized,
    WR: WorkspaceRepository + ?Sized,
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
        // 0–4. Enforce PoP sender-device binding and device ownership
        verify_pop_sender_and_devices(
            &self.device_repo,
            command.user_id,
            command.device_id,
            command.sender_device_id,
            command.authenticated_device_id,
        )
        .await
        .map_err(|e| {
            e.map_to(
                || SaveWorkspaceKeyError::SenderDeviceMismatch,
                || SaveWorkspaceKeyError::DeviceNotFound,
                || SaveWorkspaceKeyError::DeviceRevoked,
                SaveWorkspaceKeyError::DeviceRepository,
                || SaveWorkspaceKeyError::DeviceNotFound,
                || SaveWorkspaceKeyError::DeviceRevoked,
                SaveWorkspaceKeyError::DeviceRepository,
            )
        })?;

        // 1. Get workspace to check min_kek_version
        let workspace = self
            .workspace_repo
            .find_by_id(command.workspace_id)
            .await
            .map_err(SaveWorkspaceKeyError::WorkspaceRepository)?
            .ok_or(SaveWorkspaceKeyError::WorkspaceNotFound)?;

        // 2. Check membership and Read permission (minimum required to access workspace keys)
        check_workspace_permission(
            &self.member_repo,
            &self.role_repo,
            command.workspace_id,
            command.user_id,
            WorkspacePermission::Read,
        )
        .await
        .map_err(SaveWorkspaceKeyError::WorkspaceAccess)?;

        // 5. Validate and create key version
        let key_version = if let Some(v) = command.key_version {
            crate::encryption::key_version_util::validate_explicit_key_version(v)
                .map_err(|_| SaveWorkspaceKeyError::InvalidKeyVersion)?
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

            crate::encryption::key_version_util::auto_resolve_key_version(
                existing_keys.iter().map(|k| k.key_version.as_i32()),
                workspace.min_kek_version,
            )
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

        Ok(SaveWorkspaceKeyResult { key: key.into() })
    }
}
