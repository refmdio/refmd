//! Create document update command
//!
//! Adds a new encrypted Yjs update to a document's CRDT log.
//! Performs server-side validation: RBAC, snapshot ref, device ownership,
//! clock verification, and update_hash verification. Envelope signature is
//! verified in presentation layer.
//! Client sends timestamp and update_hash; server re-computes and verifies match.

use domain::document::{
    DocumentId, DocumentRepository, DocumentSnapshotId, DocumentSnapshotRepository,
    DocumentUpdate, DocumentUpdateRepository, NewDocumentUpdateParams,
};
use domain::encryption::DeviceRepository;
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceMemberRepository, WorkspaceRolePermissionRepository, WorkspaceRoleRepository,
    permission,
};

use crate::util::document_update_verification;
use crate::util::workspace_access::{WorkspaceAccessError, load_document_with_permission};
use std::sync::Arc;
use thiserror::Error;

/// Alias for the verbose error type
type CduError<DR, DUR, SR, MR, RR, RPR, DevR> =
    CreateDocumentUpdateError<DR, DUR, SR, MR, RR, RPR, DevR>;

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
    /// Envelope signature (already verified in presentation layer)
    pub signature: Vec<u8>,
    /// Collab snapshot this update targets
    pub ref_snapshot_id: DocumentSnapshotId,
    /// Per-device monotonic clock
    pub clock: i32,
    /// Device signing public key (base64url)
    pub device_signing_pub_key: String,
    /// Device ID from publicData (for cross-validation against resolved device)
    pub device_id: String,
    /// Raw publicData JSON from envelope (for read-time signature verification)
    pub public_data: serde_json::Value,
    /// Client-generated Unix ms timestamp
    pub timestamp: i64,
    /// Client-computed update_hash (base64url BLAKE3 of JCS-canonical fields)
    pub client_update_hash: String,
}

/// Create document update result
#[derive(Debug)]
pub struct CreateDocumentUpdateResult {
    pub clock: i32,
    pub version: i64,
}

/// Create document update error
#[derive(Debug, Error)]
pub enum CreateDocumentUpdateError<
    DR: std::error::Error,
    DUR: std::error::Error,
    SR: std::error::Error,
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

    #[error("key version too old: minimum required is {min_version}, got {provided_version}")]
    KeyVersionTooOld {
        min_version: i32,
        provided_version: i32,
    },

    #[error("snapshot mismatch: ref_snapshot_id does not match active")]
    SnapshotMismatch,

    #[error("clock mismatch: expected next clock value")]
    ClockMismatch,

    #[error("author device not found")]
    AuthorDeviceNotFound,

    #[error("author device has been revoked")]
    AuthorDeviceRevoked,

    #[error("author device not owned by user")]
    AuthorDeviceNotOwned,

    #[error("device ID mismatch: publicData.deviceId does not match resolved device")]
    AuthorDeviceIdMismatch,

    #[error("update_hash mismatch: client hash does not match server re-computation")]
    UpdateHashMismatch,

    #[error("hash computation failed: {0}")]
    HashComputation(#[from] domain::signature::SignatureError),

    #[error("document repository error: {0}")]
    DocumentRepository(DR),

    #[error("update repository error: {0}")]
    UpdateRepository(DUR),

    #[error("snapshot repository error: {0}")]
    SnapshotRepository(SR),

    #[error("device repository error: {0}")]
    DeviceRepository(DevR),
}

crate::types::impl_app_error!(
    [DR: std::error::Error, DUR: std::error::Error, SR: std::error::Error, MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error, DevR: std::error::Error]
    CreateDocumentUpdateError<DR, DUR, SR, MR, RR, RPR, DevR>,
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
        CreateDocumentUpdateError::AuthorDeviceNotFound,
        CreateDocumentUpdateError::AuthorDeviceRevoked,
        CreateDocumentUpdateError::AuthorDeviceIdMismatch,
        CreateDocumentUpdateError::UpdateHashMismatch,
        CreateDocumentUpdateError::HashComputation(..),
    ],
    conflict: [
        CreateDocumentUpdateError::DocumentArchived,
        CreateDocumentUpdateError::ClockMismatch,
        CreateDocumentUpdateError::SnapshotMismatch,
        CreateDocumentUpdateError::KeyVersionTooOld { .. },
    ],
);

impl<DR: std::error::Error, DUR: std::error::Error, SR: std::error::Error, MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error, DevR: std::error::Error>
    CreateDocumentUpdateError<DR, DUR, SR, MR, RR, RPR, DevR>
{
    pub fn is_snapshot_mismatch(&self) -> bool {
        matches!(self, Self::SnapshotMismatch)
    }

    pub fn is_key_version_too_old(&self) -> bool {
        matches!(self, Self::KeyVersionTooOld { .. })
    }
}

crate::util::workspace_access::impl_from_load_doc_perm!([DR, DUR, SR, MR, RR, RPR, DevR] CreateDocumentUpdateError<DR, DUR, SR, MR, RR, RPR, DevR>, DR, MR, RR, RPR);

/// Create document update handler
pub struct CreateDocumentUpdateHandler<
    DR: ?Sized,
    DUR: ?Sized,
    SR: ?Sized,
    MR: ?Sized,
    RR: ?Sized,
    RPR: ?Sized,
    DevR: ?Sized,
> {
    document_repo: Arc<DR>,
    update_repo: Arc<DUR>,
    snapshot_repo: Arc<SR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
    device_repo: Arc<DevR>,
}

#[allow(clippy::type_complexity)]
impl<DR: ?Sized, DUR: ?Sized, SR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized, DevR: ?Sized>
    CreateDocumentUpdateHandler<DR, DUR, SR, MR, RR, RPR, DevR>
where
    DR: DocumentRepository,
    DUR: DocumentUpdateRepository,
    SR: DocumentSnapshotRepository,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    RPR: WorkspaceRolePermissionRepository,
    DevR: DeviceRepository,
{
    pub fn new(
        document_repo: Arc<DR>,
        update_repo: Arc<DUR>,
        snapshot_repo: Arc<SR>,
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
        role_perm_repo: Arc<RPR>,
        device_repo: Arc<DevR>,
    ) -> Self {
        Self {
            document_repo,
            update_repo,
            snapshot_repo,
            member_repo,
            role_repo,
            role_perm_repo,
            device_repo,
        }
    }

    /// Process a document update command.
    ///
    /// ## Accepted risk: RBAC TOCTOU between authorize() and persist()
    ///
    /// Authorization (document:write check) runs before persistence. A user whose
    /// access is revoked in the milliseconds between authorize() and the DB INSERT
    /// could persist one unauthorized update.
    ///
    /// **Residual impact**: the update is persisted in the DB. The WS handler's
    /// broadcast-time RBAC check (`check_and_evict_unauthorized`) evicts the sender
    /// and skips the immediate broadcast, but the update remains in the DB and may
    /// be delivered to authorized clients on subsequent delta-mode reconnections.
    ///
    /// **Mitigations** (reduce but do not eliminate the residual):
    /// 1. **Broadcast-time lazy RBAC** (websocket-scaling.md): the sender is evicted
    ///    and the immediate broadcast is skipped if the sender lost access.
    /// 2. **DEK rotation** (ADR-002/003): member removal triggers best-effort
    ///    KEK/DEK rotation, limiting the decryptable lifetime of orphaned ciphertext.
    /// 3. **Bounded window**: the race window is single-digit milliseconds, requiring
    ///    precise concurrent timing to exploit.
    ///
    /// Eliminating this entirely would require moving RBAC into the SERIALIZABLE
    /// transaction, coupling application and infrastructure layers. The risk is
    /// accepted as the standard check-then-act pattern for web applications.
    pub async fn handle(
        &self,
        command: CreateDocumentUpdateCommand,
    ) -> Result<
        CreateDocumentUpdateResult,
        CduError<DR::Error, DUR::Error, SR::Error, MR::Error, RR::Error, RPR::Error, DevR::Error>,
    > {
        self.validate_input(&command)?;
        let document = self.authorize(&command).await?;
        self.verify_snapshot_ref(&command, &document).await?;
        self.verify_device(&command).await?;
        self.persist(command).await
    }

    fn validate_input(
        &self,
        command: &CreateDocumentUpdateCommand,
    ) -> Result<(), CduError<DR::Error, DUR::Error, SR::Error, MR::Error, RR::Error, RPR::Error, DevR::Error>>
    {
        if command.nonce.len() != 24 {
            return Err(CreateDocumentUpdateError::InvalidNonceLength);
        }
        Ok(())
    }

    async fn authorize(
        &self,
        command: &CreateDocumentUpdateCommand,
    ) -> Result<
        domain::document::Document,
        CduError<DR::Error, DUR::Error, SR::Error, MR::Error, RR::Error, RPR::Error, DevR::Error>,
    > {
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

    async fn verify_snapshot_ref(
        &self,
        command: &CreateDocumentUpdateCommand,
        _document: &domain::document::Document,
    ) -> Result<(), CduError<DR::Error, DUR::Error, SR::Error, MR::Error, RR::Error, RPR::Error, DevR::Error>>
    {
        let active_snapshot = self
            .snapshot_repo
            .find_active_by_document_id(command.document_id)
            .await
            .map_err(CreateDocumentUpdateError::SnapshotRepository)?;

        match active_snapshot {
            Some((snap, _pd)) if snap.id == command.ref_snapshot_id => Ok(()),
            _ => Err(CreateDocumentUpdateError::SnapshotMismatch),
        }
    }

    async fn verify_device(
        &self,
        command: &CreateDocumentUpdateCommand,
    ) -> Result<(), CduError<DR::Error, DUR::Error, SR::Error, MR::Error, RR::Error, RPR::Error, DevR::Error>>
    {
        let signing_pub_key_bytes = base64_url::decode(&command.device_signing_pub_key)
            .map_err(|_| CreateDocumentUpdateError::AuthorDeviceNotFound)?;

        let device = self
            .device_repo
            .find_active_by_signing_pub_key(&signing_pub_key_bytes)
            .await
            .map_err(CreateDocumentUpdateError::DeviceRepository)?
            .ok_or(CreateDocumentUpdateError::AuthorDeviceNotFound)?;

        if device.is_revoked() {
            return Err(CreateDocumentUpdateError::AuthorDeviceRevoked);
        }
        if device.user_id != command.user_id {
            return Err(CreateDocumentUpdateError::AuthorDeviceNotOwned);
        }
        if device.id.to_string() != command.device_id {
            return Err(CreateDocumentUpdateError::AuthorDeviceIdMismatch);
        }

        Ok(())
    }

    async fn persist(
        &self,
        command: CreateDocumentUpdateCommand,
    ) -> Result<
        CreateDocumentUpdateResult,
        CduError<DR::Error, DUR::Error, SR::Error, MR::Error, RR::Error, RPR::Error, DevR::Error>,
    > {
        // Re-compute update_hash from client-provided fields and verify match.
        // Per update-hash.md: timestamp is client input, server re-computes and
        // rejects on mismatch.
        let update_hash = document_update_verification::compute_update_hash(
            command.document_id,
            &command.update_data,
            &command.nonce,
            command.key_version,
            command.ref_snapshot_id,
            command.clock,
            &command.device_signing_pub_key,
            command.timestamp,
        )?;

        if update_hash != command.client_update_hash {
            return Err(CreateDocumentUpdateError::UpdateHashMismatch);
        }

        let timestamp = command.timestamp;

        let update = DocumentUpdate::new(NewDocumentUpdateParams {
            document_id: command.document_id,
            update_data: command.update_data,
            nonce: command.nonce,
            key_version: command.key_version,
            update_hash,
            signature: command.signature,
            timestamp,
            snapshot_id: command.ref_snapshot_id,
            clock: command.clock,
            device_signing_pub_key: command.device_signing_pub_key,
        });

        let (_id, clock, version) = self
            .update_repo
            .save_with_clock(&update, command.ref_snapshot_id, command.public_data)
            .await
            .map_err(|e| {
                if self.update_repo.is_snapshot_mismatch(&e) {
                    CreateDocumentUpdateError::SnapshotMismatch
                } else if self.update_repo.is_key_version_too_old(&e) {
                    CreateDocumentUpdateError::KeyVersionTooOld {
                        min_version: 0, // Exact value unknown at this layer; client should re-fetch
                        provided_version: command.key_version,
                    }
                } else if self.update_repo.is_clock_mismatch(&e) {
                    CreateDocumentUpdateError::ClockMismatch
                } else {
                    CreateDocumentUpdateError::UpdateRepository(e)
                }
            })?;

        Ok(CreateDocumentUpdateResult { clock, version })
    }
}
