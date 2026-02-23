//! Create document update command
//!
//! Adds a new encrypted Yjs update to a document's CRDT log.
//! Performs server-side validation: hash verification, chain verification,
//! device ownership, and Ed25519 signature verification.
//!
//! The handler has 5 type parameters (document, update, member, role, device
//! repositories) which is inherent to this cross-cutting operation.

use domain::document::{
    DocumentId, DocumentRepository, DocumentUpdate, DocumentUpdateRepository,
    NewDocumentUpdateParams,
};
use domain::encryption::{DeviceId, DeviceRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceMemberRepository, WorkspaceRolePermissionRepository, WorkspaceRoleRepository,
    permission,
};

use crate::util::document_update_verification;
use crate::util::workspace_access::{WorkspaceAccessError, load_document_with_permission};
use std::sync::Arc;
use thiserror::Error;

/// Alias for the verbose `CreateDocumentUpdateError` with concrete associated error types.
type CduError<DR, DUR, MR, RR, RPR, DevR> = CreateDocumentUpdateError<DR, DUR, MR, RR, RPR, DevR>;

/// Create document update command
#[derive(Debug)]
pub struct CreateDocumentUpdateCommand {
    pub document_id: DocumentId,
    pub user_id: UserId,
    /// Encrypted Yjs update binary
    pub update_data: Vec<u8>,
    /// 24-byte nonce for XChaCha20-Poly1305
    pub nonce: Vec<u8>,
    /// DEK version used for encryption
    pub key_version: i32,
    /// Content-addressable hash for idempotency
    pub update_hash: String,
    /// Hash of the previous update (for hash chain)
    pub prev_update_hash: Option<String>,
    /// Ed25519 signature over the update
    pub signature: Vec<u8>,
    /// Device that authored this update
    pub author_device_id: DeviceId,
    /// Client timestamp (milliseconds since epoch)
    pub timestamp: i64,
}

/// Create document update result
#[derive(Debug)]
pub struct CreateDocumentUpdateResult {
    pub seq: i64,
}

/// Create document update error
#[derive(Debug, Error)]
pub enum CreateDocumentUpdateError<
    DR: std::error::Error,
    DUR: std::error::Error,
    MR: std::error::Error,
    RR: std::error::Error,
    RPR: std::error::Error,
    DevR: std::error::Error,
> {
    #[error("document not found")]
    DocumentNotFound,

    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

    #[error("document is archived")]
    DocumentArchived,

    #[error("invalid nonce length: expected 24 bytes")]
    InvalidNonceLength,

    #[error("invalid timestamp: outside safe integer range")]
    InvalidTimestamp,

    #[error("key version too old: minimum required is {min_version}, got {provided_version}")]
    KeyVersionTooOld {
        min_version: i32,
        provided_version: i32,
    },

    #[error("duplicate update")]
    DuplicateUpdate,

    #[error("invalid update hash")]
    InvalidUpdateHash,

    #[error("invalid prev_update_hash: does not match latest update")]
    InvalidPrevUpdateHash,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("author device not found")]
    AuthorDeviceNotFound,

    #[error("author device has been revoked")]
    AuthorDeviceRevoked,

    #[error("author device not owned by user")]
    AuthorDeviceNotOwned,

    #[error("document repository error: {0}")]
    DocumentRepository(DR),

    #[error("update repository error: {0}")]
    UpdateRepository(DUR),

    #[error("device repository error: {0}")]
    DeviceRepository(DevR),
}

crate::types::impl_app_error!(
    [DR: std::error::Error, DUR: std::error::Error, MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error, DevR: std::error::Error]
    CreateDocumentUpdateError<DR, DUR, MR, RR, RPR, DevR>,
    not_found: [
        CreateDocumentUpdateError::DocumentNotFound,
        CreateDocumentUpdateError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        CreateDocumentUpdateError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
        CreateDocumentUpdateError::AuthorDeviceNotOwned,
    ],
    invalid_input: [
        CreateDocumentUpdateError::InvalidNonceLength,
        CreateDocumentUpdateError::InvalidTimestamp,
        CreateDocumentUpdateError::KeyVersionTooOld { .. },
        CreateDocumentUpdateError::InvalidUpdateHash,
        CreateDocumentUpdateError::InvalidPrevUpdateHash,
        CreateDocumentUpdateError::InvalidSignature,
        CreateDocumentUpdateError::AuthorDeviceNotFound,
        CreateDocumentUpdateError::AuthorDeviceRevoked,
    ],
    conflict: [
        CreateDocumentUpdateError::DocumentArchived,
        CreateDocumentUpdateError::DuplicateUpdate,
    ],
);

crate::util::workspace_access::impl_from_load_doc_perm!([DR, DUR, MR, RR, RPR, DevR] CreateDocumentUpdateError<DR, DUR, MR, RR, RPR, DevR>, DR, MR, RR, RPR);

/// Create document update handler
pub struct CreateDocumentUpdateHandler<DR: ?Sized, DUR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized, DevR: ?Sized> {
    document_repo: Arc<DR>,
    update_repo: Arc<DUR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
    device_repo: Arc<DevR>,
}

// type_complexity: The 6-parameter error type is inherent to DDD with generic repository errors.
// A type alias (CduError) reduces repetition; further simplification would require trait objects.
#[allow(clippy::type_complexity)]
impl<DR: ?Sized, DUR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized, DevR: ?Sized> CreateDocumentUpdateHandler<DR, DUR, MR, RR, RPR, DevR>
where
    DR: DocumentRepository,
    DUR: DocumentUpdateRepository,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    RPR: WorkspaceRolePermissionRepository,
    DevR: DeviceRepository,
{
    pub fn new(
        document_repo: Arc<DR>,
        update_repo: Arc<DUR>,
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
        role_perm_repo: Arc<RPR>,
        device_repo: Arc<DevR>,
    ) -> Self {
        Self {
            document_repo,
            update_repo,
            member_repo,
            role_repo,
            role_perm_repo,
            device_repo,
        }
    }

    pub async fn handle(
        &self,
        command: CreateDocumentUpdateCommand,
    ) -> Result<
        CreateDocumentUpdateResult,
        CduError<DR::Error, DUR::Error, MR::Error, RR::Error, RPR::Error, DevR::Error>,
    > {
        self.validate_input(&command)?;

        let _document = self.authorize(&command).await?;

        self.verify_integrity(&command).await?;

        self.verify_author_device(&command).await?;

        self.persist(command).await
    }

    /// Phase 1: Validate nonce length and timestamp range.
    fn validate_input(
        &self,
        command: &CreateDocumentUpdateCommand,
    ) -> Result<(), CduError<DR::Error, DUR::Error, MR::Error, RR::Error, RPR::Error, DevR::Error>> {
        if command.nonce.len() != 24 {
            return Err(CreateDocumentUpdateError::InvalidNonceLength);
        }
        const MAX_SAFE_INTEGER: i64 = 9007199254740991; // 2^53 - 1
        if command.timestamp < 0 || command.timestamp > MAX_SAFE_INTEGER {
            return Err(CreateDocumentUpdateError::InvalidTimestamp);
        }
        Ok(())
    }

    /// Phase 2: Document existence, archive check, DEK version, workspace permission.
    async fn authorize(
        &self,
        command: &CreateDocumentUpdateCommand,
    ) -> Result<domain::document::Document, CduError<DR::Error, DUR::Error, MR::Error, RR::Error, RPR::Error, DevR::Error>> {
        let document = load_document_with_permission(
            &self.document_repo,
            &self.member_repo,
            &self.role_repo,
            &self.role_perm_repo,
            command.document_id,
            command.user_id,
            permission::DOCUMENT_WRITE,
        )
        .await
        .map_err(CreateDocumentUpdateError::from_load)?;

        if document.is_archived() {
            return Err(CreateDocumentUpdateError::DocumentArchived);
        }
        if command.key_version < document.min_dek_version {
            return Err(CreateDocumentUpdateError::KeyVersionTooOld {
                min_version: document.min_dek_version,
                provided_version: command.key_version,
            });
        }

        Ok(document)
    }

    /// Phase 3: Idempotency check and hash verification.
    async fn verify_integrity(
        &self,
        command: &CreateDocumentUpdateCommand,
    ) -> Result<(), CduError<DR::Error, DUR::Error, MR::Error, RR::Error, RPR::Error, DevR::Error>> {
        if self
            .update_repo
            .find_by_hash(&command.update_hash)
            .await
            .map_err(CreateDocumentUpdateError::UpdateRepository)?
            .is_some()
        {
            return Err(CreateDocumentUpdateError::DuplicateUpdate);
        }
        verify_update_hash(command).map_err(|()| CreateDocumentUpdateError::InvalidUpdateHash)?;
        Ok(())
    }

    /// Phase 4: Device ownership check and Ed25519 signature verification.
    async fn verify_author_device(
        &self,
        command: &CreateDocumentUpdateCommand,
    ) -> Result<(), CduError<DR::Error, DUR::Error, MR::Error, RR::Error, RPR::Error, DevR::Error>> {
        let device = self
            .device_repo
            .find_by_id(command.author_device_id)
            .await
            .map_err(CreateDocumentUpdateError::DeviceRepository)?
            .ok_or(CreateDocumentUpdateError::AuthorDeviceNotFound)?;

        if device.is_revoked() {
            return Err(CreateDocumentUpdateError::AuthorDeviceRevoked);
        }
        if device.user_id != command.user_id {
            return Err(CreateDocumentUpdateError::AuthorDeviceNotOwned);
        }

        document_update_verification::verify_document_update_signature(
            &device.signing_public_key,
            &command.signature,
            &command.document_id.to_string(),
            &command.update_hash,
            command.prev_update_hash.as_deref(),
            command.key_version as i64,
            command.timestamp,
        )
        .map_err(|_| CreateDocumentUpdateError::InvalidSignature)?;

        Ok(())
    }

    /// Phase 5: Create and save update atomically (seq assigned by DB, chain verified by DB).
    async fn persist(
        &self,
        command: CreateDocumentUpdateCommand,
    ) -> Result<CreateDocumentUpdateResult, CduError<DR::Error, DUR::Error, MR::Error, RR::Error, RPR::Error, DevR::Error>> {
        let update = DocumentUpdate::new(NewDocumentUpdateParams {
            document_id: command.document_id,
            seq: 0,
            update_data: command.update_data,
            nonce: command.nonce,
            key_version: command.key_version,
            update_hash: command.update_hash,
            prev_update_hash: command.prev_update_hash,
            signature: command.signature,
            author_device_id: command.author_device_id,
            timestamp: command.timestamp,
        });

        let (_id, seq) = self
            .update_repo
            .save(&update)
            .await
            .map_err(|e| {
                if self.update_repo.is_duplicate_hash(&e) {
                    CreateDocumentUpdateError::DuplicateUpdate
                } else if self.update_repo.is_chain_mismatch(&e) {
                    CreateDocumentUpdateError::InvalidPrevUpdateHash
                } else {
                    CreateDocumentUpdateError::UpdateRepository(e)
                }
            })?;

        Ok(CreateDocumentUpdateResult { seq })
    }

}

/// Verify that `BLAKE3(JCS({fields}))` matches the claimed `update_hash`.
///
/// Extracted as a module-level function because it does not need `&self`.
fn verify_update_hash(command: &CreateDocumentUpdateCommand) -> Result<(), ()> {
    document_update_verification::verify_update_hash(
        command.document_id,
        &command.update_data,
        &command.nonce,
        command.key_version,
        &command.update_hash,
        command.prev_update_hash.as_deref(),
        command.author_device_id,
        command.timestamp,
    )
    .map_err(|_| ())
}
