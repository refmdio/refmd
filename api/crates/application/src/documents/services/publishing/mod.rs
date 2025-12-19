use std::sync::Arc;

use uuid::Uuid;

use crate::core::services::errors::ServiceError;
use crate::documents::dtos::PublicDocumentSummaryDto;
use crate::documents::ports::publishing::public_repository::PublicRepository;
use crate::documents::ports::realtime::realtime_port::RealtimeEngine;
use crate::documents::use_cases::publishing::get_public::GetPublicByWorkspaceAndId;
use crate::documents::use_cases::publishing::get_status::{GetPublishStatus, PublishStatusDto};
use crate::documents::use_cases::publishing::list_workspace::ListWorkspacePublic;
use crate::documents::use_cases::publishing::publish::{PublishDocument, PublishResponseDto};
use crate::documents::use_cases::publishing::unpublish::UnpublishDocument;
use async_trait::async_trait;
use domain::access::permissions::PermissionSet;
use domain::documents::document::Document;
use domain::documents::public_policy;

pub struct PublicService {
    repo: Arc<dyn PublicRepository>,
    realtime: Arc<dyn RealtimeEngine>,
}

#[async_trait]
pub trait PublicServiceFacade: Send + Sync {
    async fn publish_document(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<PublishResponseDto, ServiceError>;

    async fn unpublish_document(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<bool, ServiceError>;

    async fn get_publish_status(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<PublishResponseDto, ServiceError>;

    async fn list_workspace_public_documents(
        &self,
        workspace_slug: &str,
    ) -> Result<Vec<PublicDocumentSummaryDto>, ServiceError>;

    async fn get_public_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> Result<Document, ServiceError>;

    async fn get_public_content_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> Result<String, ServiceError>;
}

#[async_trait]
impl PublicServiceFacade for PublicService {
    async fn publish_document(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<PublishResponseDto, ServiceError> {
        self.publish_document(workspace_id, permissions, doc_id)
            .await
    }

    async fn unpublish_document(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<bool, ServiceError> {
        self.unpublish_document(workspace_id, permissions, doc_id)
            .await
    }

    async fn get_publish_status(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<PublishResponseDto, ServiceError> {
        self.get_publish_status(workspace_id, permissions, doc_id)
            .await
    }

    async fn list_workspace_public_documents(
        &self,
        workspace_slug: &str,
    ) -> Result<Vec<PublicDocumentSummaryDto>, ServiceError> {
        self.list_workspace_public_documents(workspace_slug).await
    }

    async fn get_public_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> Result<Document, ServiceError> {
        self.get_public_by_workspace_and_id(workspace_slug, doc_id)
            .await
    }

    async fn get_public_content_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> Result<String, ServiceError> {
        self.get_public_content_by_workspace_and_id(workspace_slug, doc_id)
            .await
    }
}

impl PublicService {
    pub fn new(repo: Arc<dyn PublicRepository>, realtime: Arc<dyn RealtimeEngine>) -> Self {
        Self { repo, realtime }
    }

    pub async fn publish_document(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<PublishResponseDto, ServiceError> {
        public_policy::ensure_public_publish_allowed(permissions)
            .map_err(|_| ServiceError::Forbidden)?;
        let uc = PublishDocument {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_id, doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)
    }

    pub async fn unpublish_document(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<bool, ServiceError> {
        public_policy::ensure_public_unpublish_allowed(permissions)
            .map_err(|_| ServiceError::Forbidden)?;
        let uc = UnpublishDocument {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_id, doc_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn get_publish_status(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<PublishResponseDto, ServiceError> {
        public_policy::ensure_public_publish_allowed(permissions)
            .map_err(|_| ServiceError::Forbidden)?;
        let uc = GetPublishStatus {
            repo: self.repo.as_ref(),
        };
        let status: PublishStatusDto = uc
            .execute(workspace_id, doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        Ok(PublishResponseDto {
            slug: status.slug,
            public_url: status.public_url,
        })
    }

    pub async fn list_workspace_public_documents(
        &self,
        workspace_slug: &str,
    ) -> Result<Vec<PublicDocumentSummaryDto>, ServiceError> {
        let uc = ListWorkspacePublic {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_slug).await.map_err(ServiceError::from)
    }

    pub async fn get_public_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> Result<Document, ServiceError> {
        let uc = GetPublicByWorkspaceAndId {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_slug, doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)
    }

    pub async fn get_public_content_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> Result<String, ServiceError> {
        let exists = self
            .repo
            .public_exists_by_workspace_and_id(workspace_slug, doc_id)
            .await
            .map_err(ServiceError::from)?;
        if !exists {
            return Err(ServiceError::NotFound);
        }
        let content = self
            .realtime
            .get_content(&doc_id.to_string())
            .await
            .map_err(ServiceError::from)?
            .unwrap_or_default();
        Ok(content)
    }
}
