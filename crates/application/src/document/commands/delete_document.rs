//! Delete document command
//!
//! Permanently deletes a document from DB and storage.
//! Related data (DocumentUpdate, DocumentSnapshot, DocumentSnapshotArchive,
//! DocumentTag, DocumentLink, DocumentEncryptedKey) are automatically deleted
//! via ON DELETE CASCADE constraints in the database schema.
//!
//! For read-only state, use ArchiveDocument instead.

use std::sync::Arc;
use domain::document::{DocumentId, DocumentRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository, can_perform,
};
use thiserror::Error;

/// Delete document command
#[derive(Debug)]
pub struct DeleteDocumentCommand {
    pub document_id: DocumentId,
    pub user_id: UserId,
}

/// Delete document result
#[derive(Debug)]
pub struct DeleteDocumentResult {
    pub deleted: bool,
}

/// Delete document error
#[derive(Debug, Error)]
pub enum DeleteDocumentError<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error> {
    #[error("document not found")]
    DocumentNotFound,

    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("permission denied: cannot delete from this workspace")]
    PermissionDenied,

    #[error("cannot delete folder with children")]
    FolderNotEmpty,

    #[error("document repository error: {0}")]
    DocumentRepository(DR),

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),
}

impl<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error>
    DeleteDocumentError<DR, MR, RR>
{
    pub fn is_not_found(&self) -> bool {
        matches!(self, DeleteDocumentError::DocumentNotFound)
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            DeleteDocumentError::NotMember | DeleteDocumentError::PermissionDenied
        )
    }

    pub fn is_bad_request(&self) -> bool {
        matches!(self, DeleteDocumentError::FolderNotEmpty)
    }
}

/// Delete document handler
pub struct DeleteDocumentHandler<DR, MR, RR> {
    document_repo: Arc<DR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<DR, MR, RR> DeleteDocumentHandler<DR, MR, RR>
where
    DR: DocumentRepository,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
{
    pub fn new(document_repo: Arc<DR>, member_repo: Arc<MR>, role_repo: Arc<RR>) -> Self {
        Self {
            document_repo,
            member_repo,
            role_repo,
        }
    }

    pub async fn handle(
        &self,
        command: DeleteDocumentCommand,
    ) -> Result<DeleteDocumentResult, DeleteDocumentError<DR::Error, MR::Error, RR::Error>> {
        // 1. Get document
        let document = self
            .document_repo
            .find_by_id(command.document_id)
            .await
            .map_err(DeleteDocumentError::DocumentRepository)?
            .ok_or(DeleteDocumentError::DocumentNotFound)?;

        // 2. Check membership and get role
        let member = self
            .member_repo
            .find_by_workspace_and_user(document.workspace_id, command.user_id)
            .await
            .map_err(DeleteDocumentError::MemberRepository)?
            .ok_or(DeleteDocumentError::NotMember)?;

        // 3. Get role and check Delete permission
        let role = self
            .role_repo
            .find_by_id(member.role_id)
            .await
            .map_err(DeleteDocumentError::RoleRepository)?
            .ok_or(DeleteDocumentError::NotMember)?;

        if !can_perform(role.base_role, WorkspacePermission::Delete) {
            return Err(DeleteDocumentError::PermissionDenied);
        }

        // 4. Check if folder has children
        if document.is_folder() {
            let children = self
                .document_repo
                .find_by_parent_id(command.document_id)
                .await
                .map_err(DeleteDocumentError::DocumentRepository)?;

            if !children.is_empty() {
                return Err(DeleteDocumentError::FolderNotEmpty);
            }
        }

        // 5. Permanently delete document
        // Related data (updates, snapshots, archives, tags, links, DEKs) are deleted
        // automatically via ON DELETE CASCADE constraints in the database schema.
        self.document_repo
            .delete(command.document_id)
            .await
            .map_err(DeleteDocumentError::DocumentRepository)?;

        Ok(DeleteDocumentResult { deleted: true })
    }
}
