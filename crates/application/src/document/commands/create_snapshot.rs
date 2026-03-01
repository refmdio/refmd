//! Create collaboration snapshot command
//!
//! Creates a new CRDT checkpoint snapshot for a document.
//! Validates parent snapshot lineage and device ownership.
//! Envelope signature is verified in presentation layer.

use domain::document::{
    DocumentId, DocumentRepository, DocumentSnapshot, DocumentSnapshotId,
    DocumentSnapshotRepository, NewDocumentSnapshotParams,
};
use domain::encryption::DeviceRepository;
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceMemberRepository, WorkspaceRolePermissionRepository, WorkspaceRoleRepository,
    permission,
};
use std::collections::HashMap;

use crate::util::workspace_access::{WorkspaceAccessError, load_document_with_permission};
use std::sync::Arc;
use thiserror::Error;

/// Create snapshot command
#[derive(Debug)]
pub struct CreateSnapshotCommand {
    /// Client-generated snapshot ID (included in signed publicData)
    pub snapshot_id: DocumentSnapshotId,
    pub document_id: DocumentId,
    pub user_id: UserId,
    /// Encrypted Yjs full state
    pub data: Vec<u8>,
    /// 24-byte nonce
    pub nonce: Vec<u8>,
    pub key_version: i32,
    /// Envelope signature (already verified in presentation layer)
    pub signature: Vec<u8>,
    /// The parent snapshot ID (must match active). None = genesis snapshot.
    pub parent_snapshot_id: Option<DocumentSnapshotId>,
    /// base64url(BLAKE3 chain hash)
    pub parent_snapshot_proof: String,
    /// Clocks from the parent snapshot's update set
    pub parent_snapshot_update_clocks: HashMap<String, i64>,
    /// Device signing public key (base64url)
    pub device_signing_pub_key: String,
    /// Device ID from publicData (for cross-validation against resolved device)
    pub device_id: String,
    /// Raw publicData JSON from envelope (for read-time signature verification)
    pub public_data: serde_json::Value,
}

/// Create snapshot result
#[derive(Debug)]
pub struct CreateSnapshotResult {
    pub snapshot_id: DocumentSnapshotId,
}

/// Create snapshot error
#[derive(Debug, Error)]
pub enum CreateSnapshotError<
    DR: std::error::Error,
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

    #[error("parent snapshot mismatch: provided ID does not match active snapshot")]
    ParentSnapshotMismatch,

    #[error("parent snapshot clock mismatch")]
    ParentSnapshotClockMismatch,

    #[error("parent snapshot proof mismatch")]
    ParentSnapshotProofMismatch,

    #[error("proof computation failed: {0}")]
    ProofComputation(#[from] domain::signature::SignatureError),

    #[error("device not found")]
    DeviceNotFound,

    #[error("key version too old: minimum required is {min_version}, got {provided_version}")]
    KeyVersionTooOld {
        min_version: i32,
        provided_version: i32,
    },

    #[error("device has been revoked")]
    DeviceRevoked,

    #[error("device not owned by user")]
    DeviceNotOwned,

    #[error("device ID mismatch: publicData.deviceId does not match resolved device")]
    DeviceIdMismatch,

    #[error("duplicate snapshot ID")]
    DuplicateSnapshotId,

    #[error("no active snapshot for document")]
    NoActiveSnapshot,

    #[error("document repository error: {0}")]
    DocumentRepository(DR),

    #[error("snapshot repository error: {0}")]
    SnapshotRepository(SR),

    #[error("device repository error: {0}")]
    DeviceRepository(DevR),
}

type CsError<DR, SR, MR, RR, RPR, DevR> = CreateSnapshotError<DR, SR, MR, RR, RPR, DevR>;

crate::types::impl_app_error!(
    [DR: std::error::Error, SR: std::error::Error, MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error, DevR: std::error::Error]
    CreateSnapshotError<DR, SR, MR, RR, RPR, DevR>,
    not_found: [
        CreateSnapshotError::DocumentNotFound,
        CreateSnapshotError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        CreateSnapshotError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
        CreateSnapshotError::DeviceNotOwned,
    ],
    invalid_input: [
        CreateSnapshotError::InvalidNonceLength,
        CreateSnapshotError::ParentSnapshotProofMismatch,
        CreateSnapshotError::ProofComputation(..),
        CreateSnapshotError::DeviceNotFound,
        CreateSnapshotError::DeviceRevoked,
        CreateSnapshotError::DeviceIdMismatch,
        CreateSnapshotError::NoActiveSnapshot,
    ],
    conflict: [
        CreateSnapshotError::DocumentArchived,
        CreateSnapshotError::ParentSnapshotMismatch,
        CreateSnapshotError::ParentSnapshotClockMismatch,
        CreateSnapshotError::KeyVersionTooOld { .. },
        CreateSnapshotError::DuplicateSnapshotId,
    ],
);

crate::util::workspace_access::impl_from_load_doc_perm!([DR, SR, MR, RR, RPR, DevR] CreateSnapshotError<DR, SR, MR, RR, RPR, DevR>, DR, MR, RR, RPR);

/// Create snapshot handler
pub struct CreateSnapshotHandler<DR: ?Sized, SR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized, DevR: ?Sized> {
    document_repo: Arc<DR>,
    snapshot_repo: Arc<SR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
    device_repo: Arc<DevR>,
}

#[allow(clippy::type_complexity)]
impl<DR: ?Sized, SR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized, DevR: ?Sized>
    CreateSnapshotHandler<DR, SR, MR, RR, RPR, DevR>
where
    DR: DocumentRepository,
    SR: DocumentSnapshotRepository,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    RPR: WorkspaceRolePermissionRepository,
    DevR: DeviceRepository,
{
    pub fn new(
        document_repo: Arc<DR>,
        snapshot_repo: Arc<SR>,
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
        role_perm_repo: Arc<RPR>,
        device_repo: Arc<DevR>,
    ) -> Self {
        Self {
            document_repo,
            snapshot_repo,
            member_repo,
            role_repo,
            role_perm_repo,
            device_repo,
        }
    }

    /// Process a snapshot creation command.
    ///
    /// ## Accepted risk: RBAC TOCTOU between authorization and snapshot save
    ///
    /// Authorization (document:write check) runs before snapshot persistence. A user
    /// whose access is revoked in the milliseconds between the RBAC check and the
    /// SERIALIZABLE INSERT could persist one unauthorized snapshot. The snapshot
    /// remains in the DB and may become the active snapshot.
    ///
    /// See `CreateDocumentUpdateHandler::handle` for the full risk analysis,
    /// mitigations, and rationale for accepting this residual risk.
    pub async fn handle(
        &self,
        command: CreateSnapshotCommand,
    ) -> Result<
        CreateSnapshotResult,
        CsError<DR::Error, SR::Error, MR::Error, RR::Error, RPR::Error, DevR::Error>,
    > {
        // Phase 1: Validate input
        if command.nonce.len() != 24 {
            return Err(CreateSnapshotError::InvalidNonceLength);
        }

        // Phase 2: Authorize
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
        .map_err(CreateSnapshotError::from_load)?;

        if document.is_archived() {
            return Err(CreateSnapshotError::DocumentArchived);
        }

        if command.key_version < document.min_dek_version {
            return Err(CreateSnapshotError::KeyVersionTooOld {
                min_version: document.min_dek_version,
                provided_version: command.key_version,
            });
        }

        // Phase 3: Verify parent snapshot lineage
        let active_snapshot = self
            .snapshot_repo
            .find_active_by_document_id(command.document_id)
            .await
            .map_err(CreateSnapshotError::SnapshotRepository)?;

        match (&command.parent_snapshot_id, &active_snapshot) {
            (Some(parent_id), Some((active, _))) => {
                // Normal flow: parent must match active
                if active.id != *parent_id {
                    return Err(CreateSnapshotError::ParentSnapshotMismatch);
                }

                // Server-side proof verification (defense-in-depth):
                // Re-compute parentSnapshotProof from parent snapshot data and verify match.
                // proof = BLAKE3(JCS({ ciphertext_hash, parent_proof, snapshot_id }))
                let expected_proof =
                    crate::util::document_update_verification::compute_parent_snapshot_proof(
                        &active.ciphertext_hash,
                        &active.parent_snapshot_proof,
                        &active.id.to_string(),
                    )?;
                if command.parent_snapshot_proof != expected_proof {
                    return Err(CreateSnapshotError::ParentSnapshotProofMismatch);
                }
            }
            (Some(_), None) => {
                // Client sent a parent ID but no active snapshot exists
                return Err(CreateSnapshotError::NoActiveSnapshot);
            }
            (None, Some(_)) => {
                // Genesis requested but active snapshot already exists
                return Err(CreateSnapshotError::ParentSnapshotMismatch);
            }
            (None, None) => {
                // Genesis: no active snapshot, no parent — valid.
                // Enforce canonical genesis: parent fields must be empty.
                if !command.parent_snapshot_proof.is_empty()
                    || !command.parent_snapshot_update_clocks.is_empty()
                {
                    return Err(CreateSnapshotError::ParentSnapshotMismatch);
                }
            }
        }

        // Phase 4: Verify device (envelope signature already verified in presentation layer)
        let signing_pub_key_bytes = base64_url::decode(&command.device_signing_pub_key)
            .map_err(|_| CreateSnapshotError::DeviceNotFound)?;
        let device = self
            .device_repo
            .find_active_by_signing_pub_key(&signing_pub_key_bytes)
            .await
            .map_err(CreateSnapshotError::DeviceRepository)?
            .ok_or(CreateSnapshotError::DeviceNotFound)?;

        if device.is_revoked() {
            return Err(CreateSnapshotError::DeviceRevoked);
        }
        if device.user_id != command.user_id {
            return Err(CreateSnapshotError::DeviceNotOwned);
        }
        if device.id.to_string() != command.device_id {
            return Err(CreateSnapshotError::DeviceIdMismatch);
        }

        // New snapshot starts with version 0 (no updates yet).
        // Version is snapshot-local and resets on each new snapshot (ADR-015).
        let latest_version = 0;

        // Compute ciphertext_hash in application layer (defense-in-depth:
        // avoids trusting presentation layer computation).
        let ciphertext_hash = base64_url::encode(blake3::hash(&command.data).as_bytes());

        // Phase 6: Create and save snapshot
        let snapshot = DocumentSnapshot::new(NewDocumentSnapshotParams {
            id: command.snapshot_id,
            document_id: command.document_id,
            latest_version,
            data: command.data,
            nonce: command.nonce,
            key_version: command.key_version,
            signature: command.signature,
            ciphertext_hash,
            clocks: HashMap::new(),
            parent_snapshot_update_clocks: command.parent_snapshot_update_clocks,
            parent_snapshot_proof: command.parent_snapshot_proof,
            created_by_device: command.device_signing_pub_key,
        });

        let snapshot_id = snapshot.id;
        let outcome = self
            .snapshot_repo
            .save(&snapshot, command.parent_snapshot_id, &snapshot.parent_snapshot_update_clocks, command.public_data)
            .await
            .map_err(CreateSnapshotError::SnapshotRepository)?;

        match outcome {
            domain::document::SnapshotSaveOutcome::Saved => {}
            domain::document::SnapshotSaveOutcome::ParentMismatch => {
                return Err(CreateSnapshotError::ParentSnapshotMismatch);
            }
            domain::document::SnapshotSaveOutcome::ClockMismatch => {
                return Err(CreateSnapshotError::ParentSnapshotClockMismatch);
            }
            domain::document::SnapshotSaveOutcome::KeyVersionTooOld => {
                return Err(CreateSnapshotError::KeyVersionTooOld {
                    min_version: 0, // Exact value unknown at this layer; client should re-fetch
                    provided_version: command.key_version,
                });
            }
            domain::document::SnapshotSaveOutcome::DuplicateId => {
                return Err(CreateSnapshotError::DuplicateSnapshotId);
            }
        }

        Ok(CreateSnapshotResult { snapshot_id })
    }
}
