//! Create document update command
//!
//! Adds a new encrypted Yjs update to a document's CRDT log.
//! Performs server-side validation: hash verification, chain verification,
//! device ownership, and Ed25519 signature verification.

use domain::document::{
    DocumentId, DocumentRepository, DocumentUpdate, DocumentUpdateRepository,
    NewDocumentUpdateParams,
};
use domain::encryption::{DeviceId, DeviceRepository};
use domain::identity::UserId;
use domain::signature::{SignatureAction, build_signature_message};
use domain::workspace::{
    WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository, can_perform,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use std::sync::Arc;
use thiserror::Error;

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
    DevR: std::error::Error,
> {
    #[error("document not found")]
    DocumentNotFound,

    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("permission denied: cannot write to this document")]
    PermissionDenied,

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

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),

    #[error("device repository error: {0}")]
    DeviceRepository(DevR),
}

impl<
        DR: std::error::Error,
        DUR: std::error::Error,
        MR: std::error::Error,
        RR: std::error::Error,
        DevR: std::error::Error,
    > CreateDocumentUpdateError<DR, DUR, MR, RR, DevR>
{
    pub fn is_not_found(&self) -> bool {
        matches!(self, CreateDocumentUpdateError::DocumentNotFound)
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            CreateDocumentUpdateError::NotMember
                | CreateDocumentUpdateError::PermissionDenied
                | CreateDocumentUpdateError::AuthorDeviceNotOwned
        )
    }

    pub fn is_conflict(&self) -> bool {
        matches!(
            self,
            CreateDocumentUpdateError::DocumentArchived
                | CreateDocumentUpdateError::DuplicateUpdate
        )
    }

    pub fn is_bad_request(&self) -> bool {
        matches!(
            self,
            CreateDocumentUpdateError::InvalidNonceLength
                | CreateDocumentUpdateError::InvalidTimestamp
                | CreateDocumentUpdateError::KeyVersionTooOld { .. }
                | CreateDocumentUpdateError::InvalidUpdateHash
                | CreateDocumentUpdateError::InvalidPrevUpdateHash
                | CreateDocumentUpdateError::InvalidSignature
                | CreateDocumentUpdateError::AuthorDeviceNotFound
                | CreateDocumentUpdateError::AuthorDeviceRevoked
        )
    }
}

/// Create document update handler
pub struct CreateDocumentUpdateHandler<DR, DUR, MR, RR, DevR: ?Sized> {
    document_repo: Arc<DR>,
    update_repo: Arc<DUR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    device_repo: Arc<DevR>,
}

impl<DR, DUR, MR, RR, DevR: ?Sized> CreateDocumentUpdateHandler<DR, DUR, MR, RR, DevR>
where
    DR: DocumentRepository,
    DUR: DocumentUpdateRepository,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    DevR: DeviceRepository,
{
    pub fn new(
        document_repo: Arc<DR>,
        update_repo: Arc<DUR>,
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
        device_repo: Arc<DevR>,
    ) -> Self {
        Self {
            document_repo,
            update_repo,
            member_repo,
            role_repo,
            device_repo,
        }
    }

    pub async fn handle(
        &self,
        command: CreateDocumentUpdateCommand,
    ) -> Result<
        CreateDocumentUpdateResult,
        CreateDocumentUpdateError<DR::Error, DUR::Error, MR::Error, RR::Error, DevR::Error>,
    > {
        // 1. Validate nonce length (24 bytes for XChaCha20-Poly1305)
        if command.nonce.len() != 24 {
            return Err(CreateDocumentUpdateError::InvalidNonceLength);
        }

        // 1.5. Validate timestamp is within JS safe integer range (prevents JCS panic)
        const MAX_SAFE_INTEGER: i64 = 9007199254740991; // 2^53 - 1
        if command.timestamp < 0 || command.timestamp > MAX_SAFE_INTEGER {
            return Err(CreateDocumentUpdateError::InvalidTimestamp);
        }

        // 2. Get document to verify it exists and get workspace_id
        let document = self
            .document_repo
            .find_by_id(command.document_id)
            .await
            .map_err(CreateDocumentUpdateError::DocumentRepository)?
            .ok_or(CreateDocumentUpdateError::DocumentNotFound)?;

        // 3. Check if document is archived
        if document.is_archived() {
            return Err(CreateDocumentUpdateError::DocumentArchived);
        }

        // 3.5. Check DEK version meets minimum requirement (after key rotation)
        if command.key_version < document.min_dek_version {
            return Err(CreateDocumentUpdateError::KeyVersionTooOld {
                min_version: document.min_dek_version,
                provided_version: command.key_version,
            });
        }

        // 4. Check membership and get role
        let member = self
            .member_repo
            .find_by_workspace_and_user(document.workspace_id, command.user_id)
            .await
            .map_err(CreateDocumentUpdateError::MemberRepository)?
            .ok_or(CreateDocumentUpdateError::NotMember)?;

        // 5. Get role and check Write permission
        let role = self
            .role_repo
            .find_by_id(member.role_id)
            .await
            .map_err(CreateDocumentUpdateError::RoleRepository)?
            .ok_or(CreateDocumentUpdateError::NotMember)?;

        if !can_perform(role.base_role, WorkspacePermission::Write) {
            return Err(CreateDocumentUpdateError::PermissionDenied);
        }

        // 6. Idempotency check: reject duplicate update_hash
        if self
            .update_repo
            .find_by_hash(&command.update_hash)
            .await
            .map_err(CreateDocumentUpdateError::UpdateRepository)?
            .is_some()
        {
            return Err(CreateDocumentUpdateError::DuplicateUpdate);
        }

        // 7. Hash verification: BLAKE3(JCS({fields})) must match update_hash
        {
            #[derive(Serialize)]
            struct UpdateHashInput<'a> {
                created_by_device_id: &'a str,
                document_id: &'a str,
                encrypted_content: &'a str,
                key_version: i64,
                nonce: &'a str,
                prev_update_hash: Option<&'a str>,
                timestamp: i64,
            }

            let encrypted_content_b64 = base64_url::encode(&command.update_data);
            let nonce_b64 = base64_url::encode(&command.nonce);

            let input = UpdateHashInput {
                created_by_device_id: &command.author_device_id.to_string(),
                document_id: &command.document_id.to_string(),
                encrypted_content: &encrypted_content_b64,
                key_version: command.key_version as i64,
                nonce: &nonce_b64,
                prev_update_hash: command.prev_update_hash.as_deref(),
                timestamp: command.timestamp,
            };

            // JCS canonicalize (BTreeMap sort) then BLAKE3
            let canonical = {
                let value = serde_json::to_value(&input)
                    .expect("UpdateHashInput serialization should not fail");
                let sorted = domain::signature::sort_value_public(value);
                serde_json::to_vec(&sorted)
                    .expect("sorted value serialization should not fail")
            };
            let computed_hash = blake3::hash(&canonical);
            let computed_hash_b64 = base64_url::encode(computed_hash.as_bytes());
            if computed_hash_b64 != command.update_hash {
                return Err(CreateDocumentUpdateError::InvalidUpdateHash);
            }
        }

        // 8. Chain verification is done atomically in the DB save (F2)

        // 9. Device ownership verification
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

        // 10. Ed25519 signature verification
        verify_document_update_signature(
            &device.signing_public_key,
            &command.signature,
            &command.document_id.to_string(),
            &command.update_hash,
            command.prev_update_hash.as_deref(),
            command.key_version as i64,
            command.timestamp,
        )
        .map_err(|_| CreateDocumentUpdateError::InvalidSignature)?;

        // 11. Create and save update atomically (seq assigned by DB, chain verified by DB)
        let update = DocumentUpdate::new(NewDocumentUpdateParams {
            document_id: command.document_id,
            seq: 0, // Will be assigned by DB
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
                if DUR::is_duplicate_hash(&e) {
                    CreateDocumentUpdateError::DuplicateUpdate
                } else if DUR::is_chain_mismatch(&e) {
                    CreateDocumentUpdateError::InvalidPrevUpdateHash
                } else {
                    CreateDocumentUpdateError::UpdateRepository(e)
                }
            })?;

        Ok(CreateDocumentUpdateResult { seq })
    }
}

/// Verify Ed25519 signature over document update metadata using JCS
fn verify_document_update_signature(
    signing_public_key: &[u8],
    signature: &[u8],
    document_id: &str,
    update_hash: &str,
    prev_update_hash: Option<&str>,
    key_version: i64,
    timestamp: i64,
) -> Result<(), ed25519_dalek::SignatureError> {
    // Parse signing public key
    let pk_bytes: [u8; 32] = signing_public_key
        .try_into()
        .map_err(|_| ed25519_dalek::SignatureError::new())?;
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes)?;

    // Build JCS signature payload
    #[derive(Serialize)]
    struct DocumentUpdatePayload<'a> {
        document_id: &'a str,
        key_version: i64,
        prev_update_hash: Option<&'a str>,
        timestamp: i64,
        update_hash: &'a str,
    }

    let message = build_signature_message(
        SignatureAction::DocumentUpdate,
        &DocumentUpdatePayload {
            document_id,
            key_version,
            prev_update_hash,
            timestamp,
            update_hash,
        },
    );

    // Parse signature
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| ed25519_dalek::SignatureError::new())?;
    let sig = Signature::from_bytes(&sig_bytes);

    // Verify
    verifying_key.verify(&message, &sig)
}
