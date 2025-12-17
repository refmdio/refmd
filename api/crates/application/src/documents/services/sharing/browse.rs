use domain::documents::share;

use crate::core::services::errors::ServiceError;
use crate::documents::dtos::{ShareBrowseResponseDto, ShareDocumentDto};
use crate::documents::use_cases::sharing::browse_share::BrowseShare;
use crate::documents::use_cases::sharing::validate_share::ValidateShare;

use super::{ShareDocumentMeta, ShareService};

impl ShareService {
    pub async fn validate_token(
        &self,
        token: &str,
    ) -> Result<Option<ShareDocumentDto>, ServiceError> {
        let uc = ValidateShare {
            repo: self.repo.as_ref(),
        };
        uc.execute(token).await.map_err(ServiceError::from)
    }

    pub async fn resolve_share_context(
        &self,
        token: &str,
    ) -> Result<Option<share::ShareContext>, ServiceError> {
        self.repo
            .resolve_share_by_token(token)
            .await
            .map_err(ServiceError::from)
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

    pub async fn share_document_meta(
        &self,
        token: &str,
    ) -> Result<Option<ShareDocumentMeta>, ServiceError> {
        let meta = self
            .repo
            .get_share_document_meta(token)
            .await
            .map_err(ServiceError::from)?
            .map(|m| ShareDocumentMeta {
                document_id: m.document_id,
                owner_id: m.owner_id,
                workspace_id: m.workspace_id,
            });
        Ok(meta)
    }
}
