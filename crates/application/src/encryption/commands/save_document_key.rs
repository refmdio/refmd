//! Save document key command
//!
//! Saves an encrypted DEK for a document.
//! Requires workspace membership with Write permission.

use domain::document::{DocumentId, DocumentRepository};
use domain::encryption::{DocumentEncryptedKey, DocumentEncryptedKeyRepository, KeyVersion};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository, can_perform,
};
use std::sync::Arc;
use thiserror::Error;

/// Save document key command
#[derive(Debug)]
pub struct SaveDocumentKeyCommand {
    pub document_id: DocumentId,
    pub user_id: UserId,
    /// Key version (default: 1 for new keys)
    pub key_version: Option<u32>,
    /// Encrypted DEK (encrypted with workspace KEK)
    pub encrypted_dek: Vec<u8>,
    /// Encryption nonce
    pub nonce: Vec<u8>,
    /// Whether this is the active key version
    pub is_active: bool,
}

/// Save document key result
#[derive(Debug)]
pub struct SaveDocumentKeyResult {
    pub key: DocumentEncryptedKey,
}

/// Save document key error
#[derive(Debug, Error)]
pub enum SaveDocumentKeyError<
    DKR: std::error::Error,
    DR: std::error::Error,
    MR: std::error::Error,
    RR: std::error::Error,
> {
    #[error("document not found")]
    DocumentNotFound,

    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("permission denied: cannot write to this workspace")]
    PermissionDenied,

    #[error("invalid key version: must be between 1 and {}", i32::MAX)]
    InvalidKeyVersion,

    #[error("key version too old: minimum required is {min_version}, got {provided_version}")]
    KeyVersionTooOld {
        min_version: i32,
        provided_version: i32,
    },

    #[error("document key repository error: {0}")]
    DocumentKeyRepository(DKR),

    #[error("document repository error: {0}")]
    DocumentRepository(DR),

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),
}

impl<DKR: std::error::Error, DR: std::error::Error, MR: std::error::Error, RR: std::error::Error>
    SaveDocumentKeyError<DKR, DR, MR, RR>
{
    pub fn is_not_found(&self) -> bool {
        matches!(self, SaveDocumentKeyError::DocumentNotFound)
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            SaveDocumentKeyError::NotMember | SaveDocumentKeyError::PermissionDenied
        )
    }

    pub fn is_bad_request(&self) -> bool {
        matches!(
            self,
            SaveDocumentKeyError::InvalidKeyVersion | SaveDocumentKeyError::KeyVersionTooOld { .. }
        )
    }
}

/// Save document key handler
pub struct SaveDocumentKeyHandler<DKR, DR, MR, RR> {
    document_key_repo: Arc<DKR>,
    document_repo: Arc<DR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<DKR, DR, MR, RR> SaveDocumentKeyHandler<DKR, DR, MR, RR>
where
    DKR: DocumentEncryptedKeyRepository,
    DR: DocumentRepository,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
{
    pub fn new(
        document_key_repo: Arc<DKR>,
        document_repo: Arc<DR>,
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
    ) -> Self {
        Self {
            document_key_repo,
            document_repo,
            member_repo,
            role_repo,
        }
    }

    pub async fn handle(
        &self,
        command: SaveDocumentKeyCommand,
    ) -> Result<
        SaveDocumentKeyResult,
        SaveDocumentKeyError<DKR::Error, DR::Error, MR::Error, RR::Error>,
    > {
        // 1. Get document to find workspace
        let mut document = self
            .document_repo
            .find_by_id(command.document_id)
            .await
            .map_err(SaveDocumentKeyError::DocumentRepository)?
            .ok_or(SaveDocumentKeyError::DocumentNotFound)?;

        // 2. Check membership
        let member = self
            .member_repo
            .find_by_workspace_and_user(document.workspace_id, command.user_id)
            .await
            .map_err(SaveDocumentKeyError::MemberRepository)?
            .ok_or(SaveDocumentKeyError::NotMember)?;

        // 3. Get role and check Write permission
        let role = self
            .role_repo
            .find_by_id(member.role_id)
            .await
            .map_err(SaveDocumentKeyError::RoleRepository)?
            .ok_or(SaveDocumentKeyError::NotMember)?;

        if !can_perform(role.base_role, WorkspacePermission::Write) {
            return Err(SaveDocumentKeyError::PermissionDenied);
        }

        // 4. Validate and create key version
        let key_version = if let Some(v) = command.key_version {
            // Validate key version is positive and within i32 range
            if v == 0 || v > i32::MAX as u32 {
                return Err(SaveDocumentKeyError::InvalidKeyVersion);
            }
            KeyVersion::new(v as i32)
        } else {
            // Auto-determine: max(existing) + 1, at least min_dek_version
            let existing_keys = self
                .document_key_repo
                .find_by_document_id(command.document_id)
                .await
                .map_err(SaveDocumentKeyError::DocumentKeyRepository)?;
            let max_version = existing_keys
                .iter()
                .map(|k| k.key_version.as_i32())
                .max()
                .unwrap_or(0);
            let next = std::cmp::max(max_version + 1, document.min_dek_version);
            KeyVersion::new(next)
        };

        // 5. Check min_dek_version constraint
        let key_version_i32 = key_version.as_i32();
        if key_version_i32 < document.min_dek_version {
            return Err(SaveDocumentKeyError::KeyVersionTooOld {
                min_version: document.min_dek_version,
                provided_version: key_version_i32,
            });
        }

        let key = DocumentEncryptedKey::new(
            command.document_id,
            key_version,
            command.encrypted_dek,
            command.nonce,
            command.is_active,
        );

        // 6. Save key
        self.document_key_repo
            .save(&key)
            .await
            .map_err(SaveDocumentKeyError::DocumentKeyRepository)?;

        // 7. Auto-clear needs_dek_rotation if the new key meets min_dek_version
        if key_version_i32 >= document.min_dek_version && document.needs_dek_rotation {
            document.clear_dek_rotation_flag();
            self.document_repo
                .save(&document)
                .await
                .map_err(SaveDocumentKeyError::DocumentRepository)?;
        }

        Ok(SaveDocumentKeyResult { key })
    }
}
