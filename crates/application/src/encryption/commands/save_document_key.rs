//! Save document key command
//!
//! Saves an encrypted DEK for a document.
//! Requires workspace membership with Write permission.

use crate::dto::DocumentEncryptedKeyDto;
use domain::document::{DocumentId, DocumentRepository};
use domain::encryption::{DocumentEncryptedKey, DocumentEncryptedKeyRepository};
use domain::identity::UserId;
use domain::workspace::{WorkspaceMemberRepository, WorkspaceRolePermissionRepository, WorkspaceRoleRepository, permission};
use std::sync::Arc;

use crate::util::workspace_access::{WorkspaceAccessError, load_document_with_permission};
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
    pub key: DocumentEncryptedKeyDto,
}

/// Save document key error
#[derive(Debug, Error)]
pub enum SaveDocumentKeyError<
    DKR: std::error::Error,
    DR: std::error::Error,
    MR: std::error::Error,
    RR: std::error::Error,
    RPR: std::error::Error,
> {
    #[error("document not found")]
    DocumentNotFound,

    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

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
}

crate::types::impl_app_error!(
    [DKR: std::error::Error, DR: std::error::Error, MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error]
    SaveDocumentKeyError<DKR, DR, MR, RR, RPR>,
    not_found: [
        SaveDocumentKeyError::DocumentNotFound,
        SaveDocumentKeyError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        SaveDocumentKeyError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
    ],
    invalid_input: [
        SaveDocumentKeyError::InvalidKeyVersion,
        SaveDocumentKeyError::KeyVersionTooOld { .. },
    ],
);

crate::util::workspace_access::impl_from_load_doc_perm!([DKR, DR, MR, RR, RPR] SaveDocumentKeyError<DKR, DR, MR, RR, RPR>, DR, MR, RR, RPR);

/// Save document key handler
pub struct SaveDocumentKeyHandler<DKR: ?Sized, DR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized> {
    document_key_repo: Arc<DKR>,
    document_repo: Arc<DR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
}

impl<DKR, DR, MR, RR, RPR> SaveDocumentKeyHandler<DKR, DR, MR, RR, RPR>
where
    DKR: DocumentEncryptedKeyRepository + ?Sized,
    DR: DocumentRepository + ?Sized,
    MR: WorkspaceMemberRepository + ?Sized,
    RR: WorkspaceRoleRepository + ?Sized,
    RPR: WorkspaceRolePermissionRepository + ?Sized,
{
    pub fn new(
        document_key_repo: Arc<DKR>,
        document_repo: Arc<DR>,
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
        role_perm_repo: Arc<RPR>,
    ) -> Self {
        Self {
            document_key_repo,
            document_repo,
            member_repo,
            role_repo,
            role_perm_repo,
        }
    }

    pub async fn handle(
        &self,
        command: SaveDocumentKeyCommand,
    ) -> Result<
        SaveDocumentKeyResult,
        SaveDocumentKeyError<DKR::Error, DR::Error, MR::Error, RR::Error, RPR::Error>,
    > {
        let mut document = load_document_with_permission(
            &self.document_repo,
            &self.member_repo,
            &self.role_repo,
            &self.role_perm_repo,
            command.document_id,
            command.user_id,
            permission::DOCUMENT_WRITE,
        )
        .await
        .map_err(SaveDocumentKeyError::from_load)?;

        // Validate and create key version
        let key_version = if let Some(v) = command.key_version {
            crate::encryption::key_version_util::validate_explicit_key_version(v)
                .map_err(|_| SaveDocumentKeyError::InvalidKeyVersion)?
        } else {
            // Auto-determine: max(existing) + 1, at least min_dek_version
            let existing_keys = self
                .document_key_repo
                .find_by_document_id(command.document_id)
                .await
                .map_err(SaveDocumentKeyError::DocumentKeyRepository)?;
            crate::encryption::key_version_util::auto_resolve_key_version(
                existing_keys.iter().map(|k| k.key_version.as_i32()),
                document.min_dek_version,
            )
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

        Ok(SaveDocumentKeyResult { key: key.into() })
    }
}
