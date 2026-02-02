//! Get document key query
//!
//! Retrieves the active DEK for a document.
//! Requires workspace membership with Read permission.

use std::sync::Arc;
use domain::document::{DocumentId, DocumentRepository};
use domain::encryption::{DocumentEncryptedKey, DocumentEncryptedKeyRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository, can_perform,
};
use thiserror::Error;

/// Get document key query
#[derive(Debug)]
pub struct GetDocumentKeyQuery {
    pub document_id: DocumentId,
    pub user_id: UserId,
}

/// Get document key result
#[derive(Debug)]
pub struct GetDocumentKeyResult {
    pub key: DocumentEncryptedKey,
}

/// Get document key error
#[derive(Debug, Error)]
pub enum GetDocumentKeyError<
    DKR: std::error::Error,
    DR: std::error::Error,
    MR: std::error::Error,
    RR: std::error::Error,
> {
    #[error("document not found")]
    DocumentNotFound,

    #[error("document key not found")]
    KeyNotFound,

    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("permission denied: cannot read from this workspace")]
    PermissionDenied,

    #[error("document key repository error: {0}")]
    DocumentKeyRepository(DKR),

    #[error("document repository error: {0}")]
    DocumentRepository(DR),

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),
}

impl<
        DKR: std::error::Error,
        DR: std::error::Error,
        MR: std::error::Error,
        RR: std::error::Error,
    > GetDocumentKeyError<DKR, DR, MR, RR>
{
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            GetDocumentKeyError::DocumentNotFound | GetDocumentKeyError::KeyNotFound
        )
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            GetDocumentKeyError::NotMember | GetDocumentKeyError::PermissionDenied
        )
    }
}

/// Get document key handler
pub struct GetDocumentKeyHandler<DKR, DR, MR, RR> {
    document_key_repo: Arc<DKR>,
    document_repo: Arc<DR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<DKR, DR, MR, RR> GetDocumentKeyHandler<DKR, DR, MR, RR>
where
    DKR: DocumentEncryptedKeyRepository,
    DR: DocumentRepository,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
{
    pub fn new(
        document_key_repo: Arc<DKR>,
        document_repo: Arc<DR>,
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
    ) -> Self {
        Self {
            document_key_repo,
            document_repo,
            member_repo,
            role_repo,
        }
    }

    pub async fn handle(
        &self,
        query: GetDocumentKeyQuery,
    ) -> Result<GetDocumentKeyResult, GetDocumentKeyError<DKR::Error, DR::Error, MR::Error, RR::Error>>
    {
        // 1. Get document to find workspace
        let document = self
            .document_repo
            .find_by_id(query.document_id)
            .await
            .map_err(GetDocumentKeyError::DocumentRepository)?
            .ok_or(GetDocumentKeyError::DocumentNotFound)?;

        // 2. Check membership
        let member = self
            .member_repo
            .find_by_workspace_and_user(document.workspace_id, query.user_id)
            .await
            .map_err(GetDocumentKeyError::MemberRepository)?
            .ok_or(GetDocumentKeyError::NotMember)?;

        // 3. Get role and check Read permission
        let role = self
            .role_repo
            .find_by_id(member.role_id)
            .await
            .map_err(GetDocumentKeyError::RoleRepository)?
            .ok_or(GetDocumentKeyError::NotMember)?;

        if !can_perform(role.base_role, WorkspacePermission::Read) {
            return Err(GetDocumentKeyError::PermissionDenied);
        }

        // 4. Get active key for document
        let key = self
            .document_key_repo
            .find_active_by_document_id(query.document_id)
            .await
            .map_err(GetDocumentKeyError::DocumentKeyRepository)?
            .ok_or(GetDocumentKeyError::KeyNotFound)?;

        Ok(GetDocumentKeyResult { key })
    }
}
