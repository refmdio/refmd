//! Get document query
//!
//! Retrieves a single document with RBAC permission check.

use std::sync::Arc;
use domain::document::{Document, DocumentId, DocumentRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository, can_perform,
};
use thiserror::Error;

/// Get document query
#[derive(Debug)]
pub struct GetDocumentQuery {
    pub document_id: DocumentId,
    pub user_id: UserId,
}

/// Get document result
#[derive(Debug)]
pub struct GetDocumentResult {
    pub document: Document,
}

/// Get document error
#[derive(Debug, Error)]
pub enum GetDocumentError<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error> {
    #[error("document not found")]
    DocumentNotFound,

    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("permission denied: cannot read from this workspace")]
    PermissionDenied,

    #[error("document repository error: {0}")]
    DocumentRepository(DR),

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),
}

impl<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error>
    GetDocumentError<DR, MR, RR>
{
    pub fn is_not_found(&self) -> bool {
        matches!(self, GetDocumentError::DocumentNotFound)
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            GetDocumentError::NotMember | GetDocumentError::PermissionDenied
        )
    }
}

/// Get document handler
pub struct GetDocumentHandler<DR, MR, RR> {
    document_repo: Arc<DR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<DR, MR, RR> GetDocumentHandler<DR, MR, RR>
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
        query: GetDocumentQuery,
    ) -> Result<GetDocumentResult, GetDocumentError<DR::Error, MR::Error, RR::Error>> {
        // 1. Get document
        let document = self
            .document_repo
            .find_by_id(query.document_id)
            .await
            .map_err(GetDocumentError::DocumentRepository)?
            .ok_or(GetDocumentError::DocumentNotFound)?;

        // 2. Check membership
        let member = self
            .member_repo
            .find_by_workspace_and_user(document.workspace_id, query.user_id)
            .await
            .map_err(GetDocumentError::MemberRepository)?
            .ok_or(GetDocumentError::NotMember)?;

        // 3. Get role and check Read permission
        let role = self
            .role_repo
            .find_by_id(member.role_id)
            .await
            .map_err(GetDocumentError::RoleRepository)?
            .ok_or(GetDocumentError::NotMember)?;

        if !can_perform(role.base_role, WorkspacePermission::Read) {
            return Err(GetDocumentError::PermissionDenied);
        }

        Ok(GetDocumentResult { document })
    }
}
