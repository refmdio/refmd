//! List documents query
//!
//! Lists documents in a workspace with RBAC permission check.

use domain::document::{DocumentId, DocumentRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspaceRolePermissionRepository,
    WorkspaceRoleRepository, permission,
};

use crate::dto::DocumentDto;
use crate::util::workspace_access::{WorkspaceAccessError, check_workspace_permission};
use std::sync::Arc;
use thiserror::Error;

/// List documents query
#[derive(Debug)]
pub struct ListDocumentsQuery {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    /// Filter by parent (None = root documents, Some(id) = children of id)
    pub parent_id: Option<Option<DocumentId>>,
    /// Include archived documents
    pub include_archived: bool,
}

/// List documents result
#[derive(Debug)]
pub struct ListDocumentsResult {
    pub documents: Vec<DocumentDto>,
}

/// List documents error
#[derive(Debug, Error)]
pub enum ListDocumentsError<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error> {
    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

    #[error("parent document not found in this workspace")]
    ParentNotFound,

    #[error("document repository error: {0}")]
    DocumentRepository(DR),
}

impl<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error>
    crate::types::AppError for ListDocumentsError<DR, MR, RR, RPR>
{
    fn is_access_denied(&self) -> bool {
        matches!(
            self,
            ListDocumentsError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied)
        )
    }

    fn is_not_found(&self) -> bool {
        matches!(
            self,
            ListDocumentsError::ParentNotFound
                | ListDocumentsError::WorkspaceAccess(WorkspaceAccessError::NotMember)
        )
    }
}

/// List documents handler
pub struct ListDocumentsHandler<DR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized> {
    document_repo: Arc<DR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
}

impl<DR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized> ListDocumentsHandler<DR, MR, RR, RPR>
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
        query: ListDocumentsQuery,
    ) -> Result<ListDocumentsResult, ListDocumentsError<DR::Error, MR::Error, RR::Error, RPR::Error>> {
        // 1. Check membership and Read permission
        check_workspace_permission(
            &self.member_repo,
            &self.role_repo,
            &self.role_perm_repo,
            query.workspace_id,
            query.user_id,
            permission::DOCUMENT_READ,
        )
        .await
        .map_err(ListDocumentsError::WorkspaceAccess)?;

        // 3. Fetch documents based on filter
        let documents = match query.parent_id {
            Some(Some(parent_id)) => {
                // Verify parent exists and belongs to the requested workspace
                let parent = self
                    .document_repo
                    .find_by_id(parent_id)
                    .await
                    .map_err(ListDocumentsError::DocumentRepository)?
                    .ok_or(ListDocumentsError::ParentNotFound)?;

                // Security check: parent must be in the same workspace
                if parent.workspace_id != query.workspace_id {
                    return Err(ListDocumentsError::ParentNotFound);
                }

                // Children of specific parent
                self.document_repo
                    .find_by_parent_id(parent_id)
                    .await
                    .map_err(ListDocumentsError::DocumentRepository)?
            }
            Some(None) => {
                // Root documents only
                self.document_repo
                    .find_roots_by_workspace_id(query.workspace_id)
                    .await
                    .map_err(ListDocumentsError::DocumentRepository)?
            }
            None => {
                // All documents in workspace
                self.document_repo
                    .find_by_workspace_id(query.workspace_id)
                    .await
                    .map_err(ListDocumentsError::DocumentRepository)?
            }
        };

        // 4. Filter archived if needed
        let documents = if query.include_archived {
            documents
        } else {
            documents.into_iter().filter(|d| !d.is_archived()).collect()
        };

        Ok(ListDocumentsResult { documents: documents.into_iter().map(Into::into).collect() })
    }
}
