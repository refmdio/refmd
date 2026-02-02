//! List documents query
//!
//! Lists documents in a workspace with RBAC permission check.

use domain::document::{Document, DocumentId, DocumentRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository,
    can_perform,
};
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
    pub documents: Vec<Document>,
}

/// List documents error
#[derive(Debug, Error)]
pub enum ListDocumentsError<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error> {
    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("permission denied: cannot read from this workspace")]
    PermissionDenied,

    #[error("parent document not found in this workspace")]
    ParentNotFound,

    #[error("document repository error: {0}")]
    DocumentRepository(DR),

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),
}

impl<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error>
    ListDocumentsError<DR, MR, RR>
{
    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            ListDocumentsError::NotMember | ListDocumentsError::PermissionDenied
        )
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, ListDocumentsError::ParentNotFound)
    }
}

/// List documents handler
pub struct ListDocumentsHandler<DR, MR, RR> {
    document_repo: Arc<DR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<DR, MR, RR> ListDocumentsHandler<DR, MR, RR>
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
        query: ListDocumentsQuery,
    ) -> Result<ListDocumentsResult, ListDocumentsError<DR::Error, MR::Error, RR::Error>> {
        // 1. Check membership
        let member = self
            .member_repo
            .find_by_workspace_and_user(query.workspace_id, query.user_id)
            .await
            .map_err(ListDocumentsError::MemberRepository)?
            .ok_or(ListDocumentsError::NotMember)?;

        // 2. Get role and check Read permission
        let role = self
            .role_repo
            .find_by_id(member.role_id)
            .await
            .map_err(ListDocumentsError::RoleRepository)?
            .ok_or(ListDocumentsError::NotMember)?;

        if !can_perform(role.base_role, WorkspacePermission::Read) {
            return Err(ListDocumentsError::PermissionDenied);
        }

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

        Ok(ListDocumentsResult { documents })
    }
}
