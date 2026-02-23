//! Get document query
//!
//! Retrieves a single document with RBAC permission check.

use domain::document::{DocumentId, DocumentRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceMemberRepository, WorkspaceRolePermissionRepository, WorkspaceRoleRepository,
    permission,
};

use crate::dto::DocumentDto;
use crate::util::workspace_access::{WorkspaceAccessError, load_document_with_permission};
use std::sync::Arc;
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
    pub document: DocumentDto,
}

/// Get document error
#[derive(Debug, Error)]
pub enum GetDocumentError<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error> {
    #[error("document not found")]
    DocumentNotFound,

    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

    #[error("document repository error: {0}")]
    DocumentRepository(DR),
}

crate::types::impl_app_error!(
    [DR: std::error::Error, MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error]
    GetDocumentError<DR, MR, RR, RPR>,
    not_found: [
        GetDocumentError::DocumentNotFound,
        GetDocumentError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        GetDocumentError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
    ],
);

crate::util::workspace_access::impl_from_load_doc_perm!([DR, MR, RR, RPR] GetDocumentError<DR, MR, RR, RPR>);

/// Get document handler
pub struct GetDocumentHandler<DR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized> {
    document_repo: Arc<DR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
}

impl<DR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized> GetDocumentHandler<DR, MR, RR, RPR>
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
        query: GetDocumentQuery,
    ) -> Result<GetDocumentResult, GetDocumentError<DR::Error, MR::Error, RR::Error, RPR::Error>> {
        let document = load_document_with_permission(
            &self.document_repo,
            &self.member_repo,
            &self.role_repo,
            &self.role_perm_repo,
            query.document_id,
            query.user_id,
            permission::DOCUMENT_READ,
        )
        .await
        .map_err(GetDocumentError::from_load)?;

        Ok(GetDocumentResult { document: document.into() })
    }
}
