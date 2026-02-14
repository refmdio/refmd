//! Delete document command
//!
//! Permanently deletes a document from DB and storage.
//! Related data (DocumentUpdate, DocumentEncryptedKey) are automatically deleted
//! via ON DELETE CASCADE constraints in the database schema.
//!
//! For read-only state, use ArchiveDocument instead.

use domain::document::{DocumentId, DocumentRepository};
use domain::identity::UserId;
use domain::workspace::{WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository};
use std::sync::Arc;

use crate::util::workspace_access::{WorkspaceAccessError, load_document_with_permission};
use thiserror::Error;

/// Delete document command
#[derive(Debug)]
pub struct DeleteDocumentCommand {
    pub document_id: DocumentId,
    pub user_id: UserId,
}

/// Delete document result
#[derive(Debug)]
pub struct DeleteDocumentResult;

/// Delete document error
#[derive(Debug, Error)]
pub enum DeleteDocumentError<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error> {
    #[error("document not found")]
    DocumentNotFound,

    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR>),

    #[error("cannot delete folder with children")]
    FolderNotEmpty,

    #[error("document repository error: {0}")]
    DocumentRepository(DR),
}

crate::types::impl_app_error!(
    [DR: std::error::Error, MR: std::error::Error, RR: std::error::Error]
    DeleteDocumentError<DR, MR, RR>,
    not_found: [
        DeleteDocumentError::DocumentNotFound,
        DeleteDocumentError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        DeleteDocumentError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
    ],
    invalid_input: [DeleteDocumentError::FolderNotEmpty],
);

crate::util::workspace_access::impl_from_load_doc_perm!([DR, MR, RR] DeleteDocumentError<DR, MR, RR>);

/// Delete document handler
pub struct DeleteDocumentHandler<DR: ?Sized, MR: ?Sized, RR: ?Sized> {
    document_repo: Arc<DR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<DR: ?Sized, MR: ?Sized, RR: ?Sized> DeleteDocumentHandler<DR, MR, RR>
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
        let document = load_document_with_permission(
            &self.document_repo,
            &self.member_repo,
            &self.role_repo,
            command.document_id,
            command.user_id,
            WorkspacePermission::Delete,
        )
        .await
        .map_err(DeleteDocumentError::from_load)?;

        // Check if folder has children
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

        Ok(DeleteDocumentResult)
    }
}
