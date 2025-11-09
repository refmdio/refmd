use std::sync::Arc;

use uuid::Uuid;

use crate::application::dto::public::PublicDocumentSummaryDto;
use crate::application::ports::public_repository::PublicRepository;
use crate::application::ports::realtime_port::RealtimeEngine;
use crate::application::services::errors::ServiceError;
use crate::application::use_cases::public::get_public::GetPublicByOwnerAndId;
use crate::application::use_cases::public::get_status::{GetPublishStatus, PublishStatusDto};
use crate::application::use_cases::public::list_user::ListUserPublic;
use crate::application::use_cases::public::publish::{PublishDocument, PublishResponseDto};
use crate::application::use_cases::public::unpublish::UnpublishDocument;
use crate::domain::documents::document::Document;

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
        user_id: Uuid,
        doc_id: Uuid,
    ) -> Result<PublishResponseDto, ServiceError> {
        let uc = PublishDocument {
            repo: self.repo.as_ref(),
        };
        uc.execute(user_id, doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)
    }

    pub async fn unpublish_document(
        &self,
        user_id: Uuid,
        doc_id: Uuid,
    ) -> Result<bool, ServiceError> {
        let uc = UnpublishDocument {
            repo: self.repo.as_ref(),
        };
        uc.execute(user_id, doc_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn get_publish_status(
        &self,
        user_id: Uuid,
        doc_id: Uuid,
    ) -> Result<PublishResponseDto, ServiceError> {
        let uc = GetPublishStatus {
            repo: self.repo.as_ref(),
        };
        let status: PublishStatusDto = uc
            .execute(user_id, doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        Ok(PublishResponseDto {
            slug: status.slug,
            public_url: status.public_url,
        })
    }

    pub async fn list_user_public_documents(
        &self,
        owner: &str,
    ) -> Result<Vec<PublicDocumentSummaryDto>, ServiceError> {
        let uc = ListUserPublic {
            repo: self.repo.as_ref(),
        };
        uc.execute(owner).await.map_err(ServiceError::from)
    }

    pub async fn get_public_by_owner_and_id(
        &self,
        owner: &str,
        doc_id: Uuid,
    ) -> Result<Document, ServiceError> {
        let uc = GetPublicByOwnerAndId {
            repo: self.repo.as_ref(),
        };
        uc.execute(owner, doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)
    }

    pub async fn get_public_content_by_owner_and_id(
        &self,
        owner: &str,
        doc_id: Uuid,
    ) -> Result<String, ServiceError> {
        let exists = self
            .repo
            .public_exists_by_owner_and_id(owner, doc_id)
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
