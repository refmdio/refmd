use std::sync::Arc;

use uuid::Uuid;

use crate::access::{self, Actor, Capability};
use crate::ports::access_repository::AccessRepository;
use crate::ports::share_access_port::ShareAccessPort;
use crate::services::errors::ServiceError;

#[derive(Clone)]
pub struct AuthorizationService {
    access_repo: Arc<dyn AccessRepository>,
    share_access: Arc<dyn ShareAccessPort>,
}

impl AuthorizationService {
    pub fn new(
        access_repo: Arc<dyn AccessRepository>,
        share_access: Arc<dyn ShareAccessPort>,
    ) -> Self {
        Self {
            access_repo,
            share_access,
        }
    }

    pub async fn resolve_document(&self, actor: &Actor, doc_id: Uuid) -> Capability {
        access::resolve_document(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
    }

    pub async fn require_view(
        &self,
        actor: &Actor,
        doc_id: Uuid,
    ) -> Result<Capability, ServiceError> {
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|_| ServiceError::Forbidden)
    }

    pub async fn require_edit(&self, actor: &Actor, doc_id: Uuid) -> Result<(), ServiceError> {
        access::require_edit(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|_| ServiceError::Forbidden)
    }
}
