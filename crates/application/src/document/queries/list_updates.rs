//! List document updates query
//!
//! Returns all encrypted Yjs updates for a document.

use domain::document::{DocumentId, DocumentRepository, DocumentUpdate, DocumentUpdateRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository, can_perform,
};
use std::sync::Arc;
use thiserror::Error;

/// List document updates query
#[derive(Debug)]
pub struct ListDocumentUpdatesQuery {
    pub document_id: DocumentId,
    pub user_id: UserId,
    /// If provided, only return updates after this sequence number
    pub after_seq: Option<i64>,
}

/// List document updates result
#[derive(Debug)]
pub struct ListDocumentUpdatesResult {
    pub updates: Vec<DocumentUpdate>,
}

/// List document updates error
#[derive(Debug, Error)]
pub enum ListDocumentUpdatesError<
    DR: std::error::Error,
    DUR: std::error::Error,
    MR: std::error::Error,
    RR: std::error::Error,
> {
    #[error("document not found")]
    DocumentNotFound,

    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("permission denied: cannot read this document")]
    PermissionDenied,

    #[error("document repository error: {0}")]
    DocumentRepository(DR),

    #[error("update repository error: {0}")]
    UpdateRepository(DUR),

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),
}

impl<DR: std::error::Error, DUR: std::error::Error, MR: std::error::Error, RR: std::error::Error>
    ListDocumentUpdatesError<DR, DUR, MR, RR>
{
    pub fn is_not_found(&self) -> bool {
        matches!(self, ListDocumentUpdatesError::DocumentNotFound)
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            ListDocumentUpdatesError::NotMember | ListDocumentUpdatesError::PermissionDenied
        )
    }
}

/// List document updates handler
pub struct ListDocumentUpdatesHandler<DR, DUR, MR, RR> {
    document_repo: Arc<DR>,
    update_repo: Arc<DUR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<DR, DUR, MR, RR> ListDocumentUpdatesHandler<DR, DUR, MR, RR>
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
        query: ListDocumentUpdatesQuery,
    ) -> Result<
        ListDocumentUpdatesResult,
        ListDocumentUpdatesError<DR::Error, DUR::Error, MR::Error, RR::Error>,
    > {
        // 1. Get document to verify it exists and get workspace_id
        let document = self
            .document_repo
            .find_by_id(query.document_id)
            .await
            .map_err(ListDocumentUpdatesError::DocumentRepository)?
            .ok_or(ListDocumentUpdatesError::DocumentNotFound)?;

        // 2. Check membership and get role
        let member = self
            .member_repo
            .find_by_workspace_and_user(document.workspace_id, query.user_id)
            .await
            .map_err(ListDocumentUpdatesError::MemberRepository)?
            .ok_or(ListDocumentUpdatesError::NotMember)?;

        // 3. Get role and check Read permission
        let role = self
            .role_repo
            .find_by_id(member.role_id)
            .await
            .map_err(ListDocumentUpdatesError::RoleRepository)?
            .ok_or(ListDocumentUpdatesError::NotMember)?;

        if !can_perform(role.base_role, WorkspacePermission::Read) {
            return Err(ListDocumentUpdatesError::PermissionDenied);
        }

        // 4. Fetch updates
        let updates = if let Some(after_seq) = query.after_seq {
            self.update_repo
                .find_by_document_id_after_seq(query.document_id, after_seq)
                .await
                .map_err(ListDocumentUpdatesError::UpdateRepository)?
        } else {
            self.update_repo
                .find_by_document_id(query.document_id)
                .await
                .map_err(ListDocumentUpdatesError::UpdateRepository)?
        };

        Ok(ListDocumentUpdatesResult { updates })
    }
}
