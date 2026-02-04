//! Create document update command
//!
//! Adds a new encrypted Yjs update to a document's CRDT log.

use domain::document::{
    DocumentId, DocumentRepository, DocumentUpdate, DocumentUpdateRepository, NewDocumentUpdateParams,
};
use domain::identity::UserId;
use domain::workspace::{WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository, can_perform};
use std::sync::Arc;
use thiserror::Error;

/// Create document update command
#[derive(Debug)]
pub struct CreateDocumentUpdateCommand {
    pub document_id: DocumentId,
    pub user_id: UserId,
    /// Base64url-encoded encrypted Yjs update binary
    pub update_data: Vec<u8>,
    /// 24-byte nonce for XChaCha20-Poly1305
    pub nonce: Vec<u8>,
    /// DEK version used for encryption
    pub key_version: i32,
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

    #[error("key version too old: minimum required is {min_version}, got {provided_version}")]
    KeyVersionTooOld { min_version: i32, provided_version: i32 },

    #[error("document repository error: {0}")]
    DocumentRepository(DR),

    #[error("update repository error: {0}")]
    UpdateRepository(DUR),

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),
}

impl<
        DR: std::error::Error,
        DUR: std::error::Error,
        MR: std::error::Error,
        RR: std::error::Error,
    > CreateDocumentUpdateError<DR, DUR, MR, RR>
{
    pub fn is_not_found(&self) -> bool {
        matches!(self, CreateDocumentUpdateError::DocumentNotFound)
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            CreateDocumentUpdateError::NotMember | CreateDocumentUpdateError::PermissionDenied
        )
    }

    pub fn is_conflict(&self) -> bool {
        matches!(self, CreateDocumentUpdateError::DocumentArchived)
    }

    pub fn is_bad_request(&self) -> bool {
        matches!(self, CreateDocumentUpdateError::InvalidNonceLength | CreateDocumentUpdateError::KeyVersionTooOld { .. })
    }
}

/// Create document update handler
pub struct CreateDocumentUpdateHandler<DR, DUR, MR, RR> {
    document_repo: Arc<DR>,
    update_repo: Arc<DUR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<DR, DUR, MR, RR> CreateDocumentUpdateHandler<DR, DUR, MR, RR>
where
    DR: DocumentRepository,
    DUR: DocumentUpdateRepository,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
{
    pub fn new(
        document_repo: Arc<DR>,
        update_repo: Arc<DUR>,
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
    ) -> Self {
        Self {
            document_repo,
            update_repo,
            member_repo,
            role_repo,
        }
    }

    pub async fn handle(
        &self,
        command: CreateDocumentUpdateCommand,
    ) -> Result<
        CreateDocumentUpdateResult,
        CreateDocumentUpdateError<DR::Error, DUR::Error, MR::Error, RR::Error>,
    > {
        // 1. Validate nonce length (24 bytes for XChaCha20-Poly1305)
        if command.nonce.len() != 24 {
            return Err(CreateDocumentUpdateError::InvalidNonceLength);
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

        // 6. Get next sequence number
        let latest_seq = self
            .update_repo
            .get_latest_seq(command.document_id)
            .await
            .map_err(CreateDocumentUpdateError::UpdateRepository)?
            .unwrap_or(0);

        let next_seq = latest_seq + 1;

        // 7. Create and save update (Phase 1C: no signature/hash)
        let update = DocumentUpdate::new(NewDocumentUpdateParams {
            document_id: command.document_id,
            seq: next_seq,
            update_data: command.update_data,
            nonce: command.nonce,
            key_version: command.key_version,
            update_hash: None,       // Phase 2
            prev_update_hash: None,  // Phase 2
            signature: None,         // Phase 2
            author_device_id: None,  // Phase 2
            timestamp: command.timestamp,
        });

        self.update_repo
            .save(&update)
            .await
            .map_err(CreateDocumentUpdateError::UpdateRepository)?;

        Ok(CreateDocumentUpdateResult { seq: next_seq })
    }
}
