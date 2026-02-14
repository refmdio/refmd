//! List document updates query
//!
//! Returns all encrypted Yjs updates for a document.

use domain::document::{DocumentId, DocumentRepository, DocumentUpdateRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository,
};

use crate::dto::DocumentUpdateDto;
use crate::util::workspace_access::{WorkspaceAccessError, load_document_with_permission};
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
    pub updates: Vec<DocumentUpdateDto>,
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

    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR>),

    #[error("document repository error: {0}")]
    DocumentRepository(DR),

    #[error("update repository error: {0}")]
    UpdateRepository(DUR),
}

crate::types::impl_app_error!(
    [DR: std::error::Error, DUR: std::error::Error, MR: std::error::Error, RR: std::error::Error]
    ListDocumentUpdatesError<DR, DUR, MR, RR>,
    not_found: [
        ListDocumentUpdatesError::DocumentNotFound,
        ListDocumentUpdatesError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        ListDocumentUpdatesError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
    ],
);

crate::util::workspace_access::impl_from_load_doc_perm!([DR, DUR, MR, RR] ListDocumentUpdatesError<DR, DUR, MR, RR>, DR, MR, RR);

/// List document updates handler
pub struct ListDocumentUpdatesHandler<DR: ?Sized, DUR: ?Sized, MR: ?Sized, RR: ?Sized> {
    document_repo: Arc<DR>,
    update_repo: Arc<DUR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<DR: ?Sized, DUR: ?Sized, MR: ?Sized, RR: ?Sized> ListDocumentUpdatesHandler<DR, DUR, MR, RR>
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
        let _document = load_document_with_permission(
            &self.document_repo,
            &self.member_repo,
            &self.role_repo,
            query.document_id,
            query.user_id,
            WorkspacePermission::Read,
        )
        .await
        .map_err(ListDocumentUpdatesError::from_load)?;

        // Fetch updates
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

        Ok(ListDocumentUpdatesResult { updates: updates.into_iter().map(Into::into).collect() })
    }
}
