use std::sync::Arc;

use uuid::Uuid;

use crate::core::services::access::{self, Actor, Capability};
use crate::core::services::errors::ServiceError;
use crate::documents::ports::access_repository::AccessRepository;
use crate::documents::ports::sharing::share_access_port::ShareAccessPort;
use async_trait::async_trait;

#[derive(Clone)]
pub struct AuthorizationService {
    access_repo: Arc<dyn AccessRepository>,
    share_access: Arc<dyn ShareAccessPort>,
}

#[async_trait]
pub trait AuthorizationServiceFacade: Send + Sync {
    async fn resolve_document(
        &self,
        actor: &Actor,
        doc_id: Uuid,
    ) -> Result<Capability, ServiceError>;

    async fn require_view(&self, actor: &Actor, doc_id: Uuid) -> Result<Capability, ServiceError>;

    async fn require_edit(&self, actor: &Actor, doc_id: Uuid) -> Result<(), ServiceError>;
}

#[async_trait]
impl AuthorizationServiceFacade for AuthorizationService {
    async fn resolve_document(
        &self,
        actor: &Actor,
        doc_id: Uuid,
    ) -> Result<Capability, ServiceError> {
        self.resolve_document(actor, doc_id).await
    }

    async fn require_view(&self, actor: &Actor, doc_id: Uuid) -> Result<Capability, ServiceError> {
        self.require_view(actor, doc_id).await
    }

    async fn require_edit(&self, actor: &Actor, doc_id: Uuid) -> Result<(), ServiceError> {
        self.require_edit(actor, doc_id).await
    }
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

    pub async fn resolve_document(
        &self,
        actor: &Actor,
        doc_id: Uuid,
    ) -> Result<Capability, ServiceError> {
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
    }

    pub async fn require_edit(&self, actor: &Actor, doc_id: Uuid) -> Result<(), ServiceError> {
        access::require_edit(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
    }
}
