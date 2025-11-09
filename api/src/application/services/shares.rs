use std::sync::Arc;

use uuid::Uuid;

use crate::application::dto::shares::{
    ActiveShareItemDto, ApplicableShareDto, CreatedShareDto, ShareBrowseResponseDto,
    ShareDocumentDto, ShareItemDto,
};
use crate::application::ports::shares_repository::SharesRepository;
use crate::application::services::errors::ServiceError;
use crate::application::use_cases::shares::browse_share::BrowseShare;
use crate::application::use_cases::shares::create_share::CreateShare;
use crate::application::use_cases::shares::delete_share::DeleteShare;
use crate::application::use_cases::shares::list_active::ListActiveShares;
use crate::application::use_cases::shares::list_applicable::ListApplicableShares;
use crate::application::use_cases::shares::list_document_shares::ListDocumentShares;
use crate::application::use_cases::shares::validate_share::ValidateShare;

pub struct ShareService {
    repo: Arc<dyn SharesRepository>,
}

impl ShareService {
    pub fn new(repo: Arc<dyn SharesRepository>) -> Self {
        Self { repo }
    }

    pub async fn create_share(
        &self,
        owner_id: Uuid,
        document_id: Uuid,
        permission: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<CreatedShareDto, ServiceError> {
        let uc = CreateShare {
            repo: self.repo.as_ref(),
        };
        uc.execute(owner_id, document_id, permission, expires_at)
            .await
            .map(|res| CreatedShareDto {
                token: res.token,
                document_id: res.document_id,
                document_type: res.document_type,
            })
            .map_err(ServiceError::from)
    }

    pub async fn list_document_shares(
        &self,
        owner_id: Uuid,
        document_id: Uuid,
    ) -> Result<Vec<ShareItemDto>, ServiceError> {
        let uc = ListDocumentShares {
            repo: self.repo.as_ref(),
        };
        uc.execute(owner_id, document_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn delete_share(&self, owner_id: Uuid, token: &str) -> Result<bool, ServiceError> {
        let uc = DeleteShare {
            repo: self.repo.as_ref(),
        };
        uc.execute(owner_id, token)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn list_applicable(
        &self,
        owner_id: Uuid,
        doc_id: Uuid,
    ) -> Result<Vec<ApplicableShareDto>, ServiceError> {
        let uc = ListApplicableShares {
            repo: self.repo.as_ref(),
        };
        uc.execute(owner_id, doc_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn validate_token(
        &self,
        token: &str,
    ) -> Result<Option<ShareDocumentDto>, ServiceError> {
        let uc = ValidateShare {
            repo: self.repo.as_ref(),
        };
        uc.execute(token).await.map_err(ServiceError::from)
    }

    pub async fn list_active(
        &self,
        owner_id: Uuid,
    ) -> Result<Vec<ActiveShareItemDto>, ServiceError> {
        let uc = ListActiveShares {
            repo: self.repo.as_ref(),
        };
        uc.execute(owner_id).await.map_err(ServiceError::from)
    }

    pub async fn browse_share(
        &self,
        token: &str,
    ) -> Result<Option<ShareBrowseResponseDto>, ServiceError> {
        let uc = BrowseShare {
            repo: self.repo.as_ref(),
        };
        uc.execute(token).await.map_err(ServiceError::from)
    }

    pub async fn materialize_folder_share(
        &self,
        owner_id: Uuid,
        token: &str,
    ) -> Result<i64, ServiceError> {
        self.repo
            .materialize_folder_share(owner_id, token)
            .await
            .map_err(|err| match err.to_string().as_str() {
                "not_found" => ServiceError::NotFound,
                "forbidden" => ServiceError::Forbidden,
                "bad_request" => ServiceError::BadRequest("invalid_share_scope"),
                _ => ServiceError::Unexpected(err),
            })
    }
}
