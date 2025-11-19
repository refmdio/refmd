use std::sync::Arc;

use uuid::Uuid;

use crate::application::dto::public::PublicDocumentSummaryDto;
use crate::application::ports::public_repository::PublicRepository;
use crate::application::ports::realtime_port::RealtimeEngine;
use crate::application::services::errors::ServiceError;
use crate::application::use_cases::public::get_public::GetPublicByWorkspaceAndId;
use crate::application::use_cases::public::get_status::{GetPublishStatus, PublishStatusDto};
use crate::application::use_cases::public::list_workspace::ListWorkspacePublic;
use crate::application::use_cases::public::publish::{PublishDocument, PublishResponseDto};
use crate::application::use_cases::public::unpublish::UnpublishDocument;
use crate::domain::documents::document::Document;
use crate::domain::workspaces::permissions::{
    PERM_PUBLIC_PUBLISH, PERM_PUBLIC_UNPUBLISH, PermissionSet,
};

pub struct PublicService {
    repo: Arc<dyn PublicRepository>,
    realtime: Arc<dyn RealtimeEngine>,
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
        ensure_public_publish_permission(permissions)?;
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
        ensure_public_unpublish_permission(permissions)?;
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
        ensure_public_publish_permission(permissions)?;
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

fn ensure_public_publish_permission(permissions: &PermissionSet) -> Result<(), ServiceError> {
    if permissions.allows(PERM_PUBLIC_PUBLISH) {
        Ok(())
    } else {
        Err(ServiceError::Forbidden)
    }
}

fn ensure_public_unpublish_permission(permissions: &PermissionSet) -> Result<(), ServiceError> {
    if permissions.allows(PERM_PUBLIC_UNPUBLISH) {
        Ok(())
    } else {
        Err(ServiceError::Forbidden)
    }
}
