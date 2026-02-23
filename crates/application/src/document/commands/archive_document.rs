//! Archive document command
//!
//! Sets a document to read-only (archived) state.
//! Archived documents can still be viewed but not edited.

use domain::document::{DocumentId, DocumentRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceMemberRepository, WorkspaceRolePermissionRepository, WorkspaceRoleRepository,
    permission,
};
use std::sync::Arc;

use crate::dto::DocumentDto;
use crate::util::workspace_access::{WorkspaceAccessError, load_document_with_permission};
use thiserror::Error;

/// Archive document command
#[derive(Debug)]
pub struct ArchiveDocumentCommand {
    pub document_id: DocumentId,
    pub user_id: UserId,
}

/// Archive document result
#[derive(Debug)]
pub struct ArchiveDocumentResult {
    pub document: DocumentDto,
}

/// Archive document error
#[derive(Debug, Error)]
pub enum ArchiveDocumentError<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error> {
    #[error("document not found")]
    DocumentNotFound,

    #[error("document already archived")]
    AlreadyArchived,

    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

    #[error("document repository error: {0}")]
    DocumentRepository(DR),
}

crate::types::impl_app_error!(
    [DR: std::error::Error, MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error]
    ArchiveDocumentError<DR, MR, RR, RPR>,
    not_found: [
        ArchiveDocumentError::DocumentNotFound,
        ArchiveDocumentError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        ArchiveDocumentError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
    ],
    conflict: [ArchiveDocumentError::AlreadyArchived],
);

crate::util::workspace_access::impl_from_load_doc_perm!([DR, MR, RR, RPR] ArchiveDocumentError<DR, MR, RR, RPR>);

/// Archive document handler
pub struct ArchiveDocumentHandler<DR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized> {
    document_repo: Arc<DR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
}

impl<DR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized> ArchiveDocumentHandler<DR, MR, RR, RPR>
where
    DR: DocumentRepository,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    RPR: WorkspaceRolePermissionRepository,
{
    pub fn new(document_repo: Arc<DR>, member_repo: Arc<MR>, role_repo: Arc<RR>, role_perm_repo: Arc<RPR>) -> Self {
        Self {
            document_repo,
            member_repo,
            role_repo,
            role_perm_repo,
        }
    }

    pub async fn handle(
        &self,
        command: ArchiveDocumentCommand,
    ) -> Result<ArchiveDocumentResult, ArchiveDocumentError<DR::Error, MR::Error, RR::Error, RPR::Error>> {
        let mut document = load_document_with_permission(
            &self.document_repo,
            &self.member_repo,
            &self.role_repo,
            &self.role_perm_repo,
            command.document_id,
            command.user_id,
            permission::DOCUMENT_ARCHIVE,
        )
        .await
        .map_err(ArchiveDocumentError::from_load)?;

        if document.is_archived() {
            return Err(ArchiveDocumentError::AlreadyArchived);
        }

        // Archive document
        document.archive();

        // 6. Save document
        self.document_repo
            .save(&document)
            .await
            .map_err(ArchiveDocumentError::DocumentRepository)?;

        // 7. If folder, archive all descendants recursively (best-effort)
        if document.is_folder()
            && let Err(e) = self.archive_descendants(command.document_id).await
        {
            tracing::warn!(
                document_id = %command.document_id,
                "partial archive: parent archived but some descendants failed: {}",
                e
            );
        }

        Ok(ArchiveDocumentResult { document: document.into() })
    }

    /// Archive all descendants of a folder iteratively (cycle-safe).
    async fn archive_descendants(&self, root_id: DocumentId) -> Result<(), DR::Error> {
        let mut stack = vec![root_id];
        let mut visited = std::collections::HashSet::new();

        while let Some(parent_id) = stack.pop() {
            if !visited.insert(parent_id) {
                continue; // cycle detected — skip
            }

            let children = self.document_repo.find_by_parent_id(parent_id).await?;

            for mut child in children {
                if !child.is_archived() {
                    child.archive();
                    self.document_repo.save(&child).await?;
                }
                if child.is_folder() {
                    stack.push(child.id);
                }
            }
        }

        Ok(())
    }
}

/// Unarchive document command
#[derive(Debug)]
pub struct UnarchiveDocumentCommand {
    pub document_id: DocumentId,
    pub user_id: UserId,
}

/// Unarchive document result
#[derive(Debug)]
pub struct UnarchiveDocumentResult {
    pub document: DocumentDto,
}

/// Unarchive document error
#[derive(Debug, Error)]
pub enum UnarchiveDocumentError<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error>
{
    #[error("document not found")]
    DocumentNotFound,

    #[error("document is not archived")]
    NotArchived,

    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

    #[error("document repository error: {0}")]
    DocumentRepository(DR),
}

crate::types::impl_app_error!(
    [DR: std::error::Error, MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error]
    UnarchiveDocumentError<DR, MR, RR, RPR>,
    not_found: [
        UnarchiveDocumentError::DocumentNotFound,
        UnarchiveDocumentError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        UnarchiveDocumentError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
    ],
    invalid_input: [UnarchiveDocumentError::NotArchived],
);

crate::util::workspace_access::impl_from_load_doc_perm!([DR, MR, RR, RPR] UnarchiveDocumentError<DR, MR, RR, RPR>);

/// Unarchive document handler
pub struct UnarchiveDocumentHandler<DR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized> {
    document_repo: Arc<DR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
}

impl<DR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized> UnarchiveDocumentHandler<DR, MR, RR, RPR>
where
    DR: DocumentRepository,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    RPR: WorkspaceRolePermissionRepository,
{
    pub fn new(document_repo: Arc<DR>, member_repo: Arc<MR>, role_repo: Arc<RR>, role_perm_repo: Arc<RPR>) -> Self {
        Self {
            document_repo,
            member_repo,
            role_repo,
            role_perm_repo,
        }
    }

    pub async fn handle(
        &self,
        command: UnarchiveDocumentCommand,
    ) -> Result<UnarchiveDocumentResult, UnarchiveDocumentError<DR::Error, MR::Error, RR::Error, RPR::Error>>
    {
        let mut document = load_document_with_permission(
            &self.document_repo,
            &self.member_repo,
            &self.role_repo,
            &self.role_perm_repo,
            command.document_id,
            command.user_id,
            permission::DOCUMENT_ARCHIVE,
        )
        .await
        .map_err(UnarchiveDocumentError::from_load)?;

        if !document.is_archived() {
            return Err(UnarchiveDocumentError::NotArchived);
        }

        // Unarchive document
        document.unarchive();

        // 6. Save document
        self.document_repo
            .save(&document)
            .await
            .map_err(UnarchiveDocumentError::DocumentRepository)?;

        Ok(UnarchiveDocumentResult { document: document.into() })
    }
}
