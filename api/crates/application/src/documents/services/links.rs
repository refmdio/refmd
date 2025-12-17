use uuid::Uuid;

use domain::documents::document::{
    BacklinkInfo as DomainBacklink, OutgoingLink as DomainOutgoingLink,
};

use crate::core::services::access::{self, Actor};
use crate::core::services::errors::ServiceError;
use crate::documents::use_cases::get_backlinks::GetBacklinks;
use crate::documents::use_cases::get_outgoing_links::GetOutgoingLinks;

use super::DocumentService;

impl DocumentService {
    pub async fn backlinks(
        &self,
        actor: &Actor,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> Result<Vec<DomainBacklink>, ServiceError> {
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|_| ServiceError::NotFound)?;

        let uc = GetBacklinks {
            repo: self.document_repo.as_ref(),
        };
        uc.execute(workspace_id, doc_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn outgoing_links(
        &self,
        actor: &Actor,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> Result<Vec<DomainOutgoingLink>, ServiceError> {
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|_| ServiceError::NotFound)?;

        let uc = GetOutgoingLinks {
            repo: self.document_repo.as_ref(),
        };
        uc.execute(workspace_id, doc_id)
            .await
            .map_err(ServiceError::from)
    }
}
