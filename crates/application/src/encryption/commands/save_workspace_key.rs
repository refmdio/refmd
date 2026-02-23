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
    WorkspaceId, WorkspaceMemberRepository, WorkspaceRepository,
};
use std::sync::Arc;

use crate::util::device_ownership::verify_pop_sender_and_devices;
use crate::util::workspace_access::{check_workspace_membership, MembershipError};
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
    DR: std::error::Error,
    WR: std::error::Error,
> {
    #[error("sender_device_id does not match authenticated device")]
    SenderDeviceMismatch,

    #[error(transparent)]
    Membership(MembershipError<MR>),

    #[error("invalid key version: must be between min_kek_version and min_kek_version + 1")]
    InvalidKeyVersion,

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
    [WKR: std::error::Error, MR: std::error::Error, DR: std::error::Error, WR: std::error::Error]
    SaveWorkspaceKeyError<WKR, MR, DR, WR>,
    not_found: [
        SaveWorkspaceKeyError::DeviceNotFound,
        SaveWorkspaceKeyError::WorkspaceNotFound,
        SaveWorkspaceKeyError::Membership(MembershipError::NotMember),
    ],
    access_denied: [
        SaveWorkspaceKeyError::SenderDeviceMismatch,
        SaveWorkspaceKeyError::DeviceNotOwned,
    ],
    invalid_input: [
        SaveWorkspaceKeyError::InvalidKeyVersion,
        SaveWorkspaceKeyError::DeviceRevoked,
    ],
    conflict: [SaveWorkspaceKeyError::KeyAlreadyExists],
);

/// Save workspace key handler
pub struct SaveWorkspaceKeyHandler<WKR: ?Sized, MR: ?Sized, DR: ?Sized, WR: ?Sized> {
    workspace_key_repo: Arc<WKR>,
    member_repo: Arc<MR>,
    device_repo: Arc<DR>,
    workspace_repo: Arc<WR>,
}

impl<WKR, MR, DR, WR> SaveWorkspaceKeyHandler<WKR, MR, DR, WR>
where
    WKR: WorkspaceEncryptedKeyRepository + ?Sized,
    MR: WorkspaceMemberRepository + ?Sized,
    DR: DeviceRepository + ?Sized,
    WR: WorkspaceRepository + ?Sized,
{
    pub fn new(
        workspace_key_repo: Arc<WKR>,
        member_repo: Arc<MR>,
        device_repo: Arc<DR>,
        workspace_repo: Arc<WR>,
    ) -> Self {
        Self {
            workspace_key_repo,
            member_repo,
            device_repo,
            workspace_repo,
        }
    }

    pub async fn handle(
        &self,
        command: SaveWorkspaceKeyCommand,
    ) -> Result<
        SaveWorkspaceKeyResult,
        SaveWorkspaceKeyError<WKR::Error, MR::Error, DR::Error, WR::Error>,
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

        // 1. Check membership first to prevent workspace existence enumeration
        check_workspace_membership(
            &self.member_repo,
            command.workspace_id,
            command.user_id,
        )
        .await
        .map_err(SaveWorkspaceKeyError::Membership)?;

        // 2. Get workspace to check min_kek_version
        let workspace = self
            .workspace_repo
            .find_by_id(command.workspace_id)
            .await
            .map_err(SaveWorkspaceKeyError::WorkspaceRepository)?
            .ok_or(SaveWorkspaceKeyError::WorkspaceNotFound)?;

        // 5. Validate and create key version
        let key_version = if let Some(v) = command.key_version {
            crate::encryption::key_version_util::validate_explicit_key_version(v)
                .map_err(|_| SaveWorkspaceKeyError::InvalidKeyVersion)?
        } else {
            // Auto-determine: max(existing) + 1, at least min_kek_version.
            //
            // Guard: if ANY user's key already exists for this workspace, reject
            // auto-version. This prevents key fork — new KEK creation is only valid
            // for brand-new workspaces (registration flow). Checking workspace-wide
            // (not just the requesting user's keys) ensures that even if two devices
            // of the same user race, the second request fails.
            //
            // Note: this is a read-then-write pattern without row locks. A true
            // concurrent race is still theoretically possible, but:
            // (a) registration runs from a single device (no concurrency in practice)
            // (b) the UPSERT in the repository means worst-case the second device
            //     overwrites the first device's key for the same (workspace, user,
            //     device, key_version), which is idempotent when the same KEK is used
            //
            // For belt-and-suspenders, callers should handle 409 (KeyAlreadyExists)
            // and fall back to fetching the existing key via backup restore.
            let existing_keys = self
                .workspace_key_repo
                .find_by_workspace_id(command.workspace_id)
                .await
                .map_err(SaveWorkspaceKeyError::WorkspaceKeyRepository)?;

            if !existing_keys.is_empty() {
                return Err(SaveWorkspaceKeyError::KeyAlreadyExists);
            }

            crate::encryption::key_version_util::auto_resolve_key_version(
                existing_keys.iter().map(|k| k.key_version.as_i32()),
                workspace.min_kek_version,
            )
        };

        // 6. Check KEK version is within the valid range.
        //    During normal operation key_version must equal min_kek_version exactly.
        //    During rotation it may also be min_kek_version + 1.
        //    Anything outside this window is invalid — a too-high value would
        //    poison MAX(key_version) and break invitation creation.
        if workspace.needs_kek_rotation {
            // During rotation: accept current or next version
            if key_version.as_i32() < workspace.min_kek_version
                || key_version.as_i32() > workspace.min_kek_version + 1
            {
                return Err(SaveWorkspaceKeyError::InvalidKeyVersion);
            }
        } else {
            // Normal operation: exact version only
            if key_version.as_i32() != workspace.min_kek_version {
                return Err(SaveWorkspaceKeyError::InvalidKeyVersion);
            }
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
