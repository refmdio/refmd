//! Get document query
//!
//! Retrieves a single document with RBAC permission check.

use domain::document::{DocumentId, DocumentRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository,
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
pub enum GetDocumentError<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error> {
    #[error("document not found")]
    DocumentNotFound,

    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR>),

    #[error("document repository error: {0}")]
    DocumentRepository(DR),
}

crate::types::impl_app_error!(
    [DR: std::error::Error, MR: std::error::Error, RR: std::error::Error]
    GetDocumentError<DR, MR, RR>,
    not_found: [
        GetDocumentError::DocumentNotFound,
        GetDocumentError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        GetDocumentError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
    ],
);

crate::util::workspace_access::impl_from_load_doc_perm!([DR, MR, RR] GetDocumentError<DR, MR, RR>);

/// Get document handler
pub struct GetDocumentHandler<DR: ?Sized, MR: ?Sized, RR: ?Sized> {
    document_repo: Arc<DR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<DR: ?Sized, MR: ?Sized, RR: ?Sized> GetDocumentHandler<DR, MR, RR>
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
        let document = load_document_with_permission(
            &self.document_repo,
            &self.member_repo,
            &self.role_repo,
            query.document_id,
            query.user_id,
            WorkspacePermission::Read,
        )
        .await
        .map_err(GetDocumentError::from_load)?;

        Ok(GetDocumentResult { document: document.into() })
    }
}
