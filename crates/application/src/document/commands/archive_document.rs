//! Archive document command
//!
//! Sets a document to read-only (archived) state.
//! Archived documents can still be viewed but not edited.

use std::sync::Arc;
use domain::document::{Document, DocumentId, DocumentRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository, can_perform,
};
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
    pub document: Document,
}

/// Archive document error
#[derive(Debug, Error)]
pub enum ArchiveDocumentError<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error> {
    #[error("document not found")]
    DocumentNotFound,

    #[error("document already archived")]
    AlreadyArchived,

    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("permission denied: cannot write to this workspace")]
    PermissionDenied,

    #[error("document repository error: {0}")]
    DocumentRepository(DR),

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),
}

impl<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error>
    ArchiveDocumentError<DR, MR, RR>
{
    pub fn is_not_found(&self) -> bool {
        matches!(self, ArchiveDocumentError::DocumentNotFound)
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            ArchiveDocumentError::NotMember | ArchiveDocumentError::PermissionDenied
        )
    }

    pub fn is_conflict(&self) -> bool {
        matches!(self, ArchiveDocumentError::AlreadyArchived)
    }
}

/// Archive document handler
pub struct ArchiveDocumentHandler<DR, MR, RR> {
    document_repo: Arc<DR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<DR, MR, RR> ArchiveDocumentHandler<DR, MR, RR>
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
        command: ArchiveDocumentCommand,
    ) -> Result<ArchiveDocumentResult, ArchiveDocumentError<DR::Error, MR::Error, RR::Error>> {
        // 1. Get document
        let mut document = self
            .document_repo
            .find_by_id(command.document_id)
            .await
            .map_err(ArchiveDocumentError::DocumentRepository)?
            .ok_or(ArchiveDocumentError::DocumentNotFound)?;

        // 2. Check if already archived
        if document.is_archived() {
            return Err(ArchiveDocumentError::AlreadyArchived);
        }

        // 3. Check membership and get role
        let member = self
            .member_repo
            .find_by_workspace_and_user(document.workspace_id, command.user_id)
            .await
            .map_err(ArchiveDocumentError::MemberRepository)?
            .ok_or(ArchiveDocumentError::NotMember)?;

        // 4. Get role and check Write permission (archive is a write operation)
        let role = self
            .role_repo
            .find_by_id(member.role_id)
            .await
            .map_err(ArchiveDocumentError::RoleRepository)?
            .ok_or(ArchiveDocumentError::NotMember)?;

        if !can_perform(role.base_role, WorkspacePermission::Write) {
            return Err(ArchiveDocumentError::PermissionDenied);
        }

        // 5. Archive document
        document.archive();

        // 6. Save document
        self.document_repo
            .save(&document)
            .await
            .map_err(ArchiveDocumentError::DocumentRepository)?;

        // 7. If folder, archive all descendants recursively
        if document.is_folder() {
            self.archive_descendants(command.document_id)
                .await
                .map_err(ArchiveDocumentError::DocumentRepository)?;
        }

        Ok(ArchiveDocumentResult { document })
    }

    /// Recursively archive all descendants of a folder
    fn archive_descendants(
        &self,
        parent_id: DocumentId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DR::Error>> + Send + '_>> {
        Box::pin(async move {
            let children = self.document_repo.find_by_parent_id(parent_id).await?;

            for mut child in children {
                if !child.is_archived() {
                    child.archive();
                    self.document_repo.save(&child).await?;
                }

                // Recursively archive children of folders
                if child.is_folder() {
                    self.archive_descendants(child.id).await?;
                }
            }

            Ok(())
        })
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
    pub document: Document,
}

/// Unarchive document error
#[derive(Debug, Error)]
pub enum UnarchiveDocumentError<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error>
{
    #[error("document not found")]
    DocumentNotFound,

    #[error("document is not archived")]
    NotArchived,

    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("permission denied: cannot write to this workspace")]
    PermissionDenied,

    #[error("document repository error: {0}")]
    DocumentRepository(DR),

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),
}

impl<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error>
    UnarchiveDocumentError<DR, MR, RR>
{
    pub fn is_not_found(&self) -> bool {
        matches!(self, UnarchiveDocumentError::DocumentNotFound)
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            UnarchiveDocumentError::NotMember | UnarchiveDocumentError::PermissionDenied
        )
    }

    pub fn is_bad_request(&self) -> bool {
        matches!(self, UnarchiveDocumentError::NotArchived)
    }
}

/// Unarchive document handler
pub struct UnarchiveDocumentHandler<DR, MR, RR> {
    document_repo: Arc<DR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<DR, MR, RR> UnarchiveDocumentHandler<DR, MR, RR>
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
        command: UnarchiveDocumentCommand,
    ) -> Result<UnarchiveDocumentResult, UnarchiveDocumentError<DR::Error, MR::Error, RR::Error>>
    {
        // 1. Get document
        let mut document = self
            .document_repo
            .find_by_id(command.document_id)
            .await
            .map_err(UnarchiveDocumentError::DocumentRepository)?
            .ok_or(UnarchiveDocumentError::DocumentNotFound)?;

        // 2. Check if archived
        if !document.is_archived() {
            return Err(UnarchiveDocumentError::NotArchived);
        }

        // 3. Check membership and get role
        let member = self
            .member_repo
            .find_by_workspace_and_user(document.workspace_id, command.user_id)
            .await
            .map_err(UnarchiveDocumentError::MemberRepository)?
            .ok_or(UnarchiveDocumentError::NotMember)?;

        // 4. Get role and check Write permission
        let role = self
            .role_repo
            .find_by_id(member.role_id)
            .await
            .map_err(UnarchiveDocumentError::RoleRepository)?
            .ok_or(UnarchiveDocumentError::NotMember)?;

        if !can_perform(role.base_role, WorkspacePermission::Write) {
            return Err(UnarchiveDocumentError::PermissionDenied);
        }

        // 5. Unarchive document
        document.unarchive();

        // 6. Save document
        self.document_repo
            .save(&document)
            .await
            .map_err(UnarchiveDocumentError::DocumentRepository)?;

        Ok(UnarchiveDocumentResult { document })
    }
}
