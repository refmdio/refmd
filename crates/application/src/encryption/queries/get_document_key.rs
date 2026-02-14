//! Get document key query
//!
//! Retrieves the active DEK for a document.
//! Requires workspace membership with Read permission.

use crate::dto::DocumentEncryptedKeyDto;
use domain::document::{DocumentId, DocumentRepository};
use domain::encryption::DocumentEncryptedKeyRepository;
use domain::identity::UserId;
use domain::workspace::{WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository};
use std::sync::Arc;

use crate::util::workspace_access::{WorkspaceAccessError, load_document_with_permission};
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
    pub key: DocumentEncryptedKeyDto,
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

    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR>),

    #[error("document key repository error: {0}")]
    DocumentKeyRepository(DKR),

    #[error("document repository error: {0}")]
    DocumentRepository(DR),
}

crate::types::impl_app_error!(
    [DKR: std::error::Error, DR: std::error::Error, MR: std::error::Error, RR: std::error::Error]
    GetDocumentKeyError<DKR, DR, MR, RR>,
    not_found: [
        GetDocumentKeyError::DocumentNotFound,
        GetDocumentKeyError::KeyNotFound,
        GetDocumentKeyError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        GetDocumentKeyError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
    ],
);

crate::util::workspace_access::impl_from_load_doc_perm!([DKR, DR, MR, RR] GetDocumentKeyError<DKR, DR, MR, RR>, DR, MR, RR);

/// Get document key handler
pub struct GetDocumentKeyHandler<DKR: ?Sized, DR: ?Sized, MR: ?Sized, RR: ?Sized> {
    document_key_repo: Arc<DKR>,
    document_repo: Arc<DR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<DKR, DR, MR, RR> GetDocumentKeyHandler<DKR, DR, MR, RR>
where
    DKR: DocumentEncryptedKeyRepository + ?Sized,
    DR: DocumentRepository + ?Sized,
    MR: WorkspaceMemberRepository + ?Sized,
    RR: WorkspaceRoleRepository + ?Sized,
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
    ) -> Result<
        GetDocumentKeyResult,
        GetDocumentKeyError<DKR::Error, DR::Error, MR::Error, RR::Error>,
    > {
        let _document = load_document_with_permission(
            &self.document_repo,
            &self.member_repo,
            &self.role_repo,
            query.document_id,
            query.user_id,
            WorkspacePermission::Read,
        )
        .await
        .map_err(GetDocumentKeyError::from_load)?;

        // Get active key for document
        let key = self
            .document_key_repo
            .find_active_by_document_id(query.document_id)
            .await
            .map_err(GetDocumentKeyError::DocumentKeyRepository)?
            .ok_or(GetDocumentKeyError::KeyNotFound)?;

        Ok(GetDocumentKeyResult { key: key.into() })
    }
}
