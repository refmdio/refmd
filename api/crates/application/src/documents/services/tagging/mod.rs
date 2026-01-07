use std::sync::Arc;

use uuid::Uuid;

use crate::core::services::errors::ServiceError;
use crate::documents::dtos::{EncryptedTagEntryDto, EncryptedTagItemDto, TagItemDto};
use crate::documents::ports::tagging::encrypted_tag_repository::EncryptedTagRepository;
use crate::documents::ports::tagging::tag_repository::TagRepository;
use crate::documents::use_cases::tagging::list_tags::ListTags;
use async_trait::async_trait;

pub struct TagService {
    repo: Arc<dyn TagRepository>,
    encrypted_tag_repo: Option<Arc<dyn EncryptedTagRepository>>,
}

#[async_trait]
pub trait TagServiceFacade: Send + Sync {
    async fn list(
        &self,
        workspace_id: Uuid,
        filter: Option<String>,
    ) -> Result<Vec<TagItemDto>, ServiceError>;

    /// List all encrypted tags in a workspace
    async fn list_encrypted_tags(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<EncryptedTagItemDto>, ServiceError>;

    /// List encrypted tags for a specific document
    async fn list_document_encrypted_tags(
        &self,
        document_id: Uuid,
    ) -> Result<Vec<EncryptedTagEntryDto>, ServiceError>;

    /// Replace all encrypted tags for a document
    async fn replace_document_encrypted_tags(
        &self,
        workspace_id: Uuid,
        document_id: Uuid,
        encrypted_tags: Vec<Vec<u8>>,
    ) -> Result<Vec<EncryptedTagEntryDto>, ServiceError>;

    /// Find documents by encrypted tag
    async fn find_documents_by_encrypted_tag(
        &self,
        workspace_id: Uuid,
        encrypted_tag: Vec<u8>,
    ) -> Result<Vec<Uuid>, ServiceError>;

    /// Find a specific encrypted tag (for filtering)
    async fn find_encrypted_tag(
        &self,
        workspace_id: Uuid,
        encrypted_tag: Vec<u8>,
    ) -> Result<Vec<EncryptedTagItemDto>, ServiceError>;
}

#[async_trait]
impl TagServiceFacade for TagService {
    async fn list(
        &self,
        workspace_id: Uuid,
        filter: Option<String>,
    ) -> Result<Vec<TagItemDto>, ServiceError> {
        self.list(workspace_id, filter).await
    }

    async fn list_encrypted_tags(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<EncryptedTagItemDto>, ServiceError> {
        self.list_encrypted_tags(workspace_id).await
    }

    async fn list_document_encrypted_tags(
        &self,
        document_id: Uuid,
    ) -> Result<Vec<EncryptedTagEntryDto>, ServiceError> {
        self.list_document_encrypted_tags(document_id).await
    }

    async fn replace_document_encrypted_tags(
        &self,
        workspace_id: Uuid,
        document_id: Uuid,
        encrypted_tags: Vec<Vec<u8>>,
    ) -> Result<Vec<EncryptedTagEntryDto>, ServiceError> {
        self.replace_document_encrypted_tags(workspace_id, document_id, encrypted_tags)
            .await
    }

    async fn find_documents_by_encrypted_tag(
        &self,
        workspace_id: Uuid,
        encrypted_tag: Vec<u8>,
    ) -> Result<Vec<Uuid>, ServiceError> {
        self.find_documents_by_encrypted_tag(workspace_id, encrypted_tag)
            .await
    }

    async fn find_encrypted_tag(
        &self,
        workspace_id: Uuid,
        encrypted_tag: Vec<u8>,
    ) -> Result<Vec<EncryptedTagItemDto>, ServiceError> {
        self.find_encrypted_tag(workspace_id, encrypted_tag).await
    }
}

impl TagService {
    pub fn new(repo: Arc<dyn TagRepository>) -> Self {
        Self {
            repo,
            encrypted_tag_repo: None,
        }
    }

    pub fn with_encrypted_tag_repo(
        mut self,
        encrypted_tag_repo: Arc<dyn EncryptedTagRepository>,
    ) -> Self {
        self.encrypted_tag_repo = Some(encrypted_tag_repo);
        self
    }

    pub async fn list(
        &self,
        workspace_id: Uuid,
        filter: Option<String>,
    ) -> Result<Vec<TagItemDto>, ServiceError> {
        let uc = ListTags {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_id, filter)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn list_encrypted_tags(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<EncryptedTagItemDto>, ServiceError> {
        let repo = self
            .encrypted_tag_repo
            .as_ref()
            .ok_or(ServiceError::BadRequest("encrypted_tags_not_enabled"))?;

        let summaries = repo
            .list_encrypted_tags(workspace_id)
            .await
            .map_err(ServiceError::from)?;

        Ok(summaries
            .into_iter()
            .map(|s| EncryptedTagItemDto {
                encrypted_tag: s.encrypted_tag,
                count: s.count,
            })
            .collect())
    }

    pub async fn list_document_encrypted_tags(
        &self,
        document_id: Uuid,
    ) -> Result<Vec<EncryptedTagEntryDto>, ServiceError> {
        let repo = self
            .encrypted_tag_repo
            .as_ref()
            .ok_or(ServiceError::BadRequest("encrypted_tags_not_enabled"))?;

        let entries = repo
            .list_document_encrypted_tags(document_id)
            .await
            .map_err(ServiceError::from)?;

        Ok(entries
            .into_iter()
            .map(|e| EncryptedTagEntryDto {
                id: e.id,
                encrypted_tag: e.encrypted_tag,
                created_at: e.created_at,
            })
            .collect())
    }

    pub async fn replace_document_encrypted_tags(
        &self,
        workspace_id: Uuid,
        document_id: Uuid,
        encrypted_tags: Vec<Vec<u8>>,
    ) -> Result<Vec<EncryptedTagEntryDto>, ServiceError> {
        let repo = self
            .encrypted_tag_repo
            .as_ref()
            .ok_or(ServiceError::BadRequest("encrypted_tags_not_enabled"))?;

        let entries = repo
            .replace_document_encrypted_tags(workspace_id, document_id, &encrypted_tags)
            .await
            .map_err(ServiceError::from)?;

        Ok(entries
            .into_iter()
            .map(|e| EncryptedTagEntryDto {
                id: e.id,
                encrypted_tag: e.encrypted_tag,
                created_at: e.created_at,
            })
            .collect())
    }

    pub async fn find_documents_by_encrypted_tag(
        &self,
        workspace_id: Uuid,
        encrypted_tag: Vec<u8>,
    ) -> Result<Vec<Uuid>, ServiceError> {
        let repo = self
            .encrypted_tag_repo
            .as_ref()
            .ok_or(ServiceError::BadRequest("encrypted_tags_not_enabled"))?;

        repo.find_documents_by_encrypted_tag(workspace_id, &encrypted_tag)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn find_encrypted_tag(
        &self,
        workspace_id: Uuid,
        encrypted_tag: Vec<u8>,
    ) -> Result<Vec<EncryptedTagItemDto>, ServiceError> {
        let repo = self
            .encrypted_tag_repo
            .as_ref()
            .ok_or(ServiceError::BadRequest("encrypted_tags_not_enabled"))?;

        let result = repo
            .find_encrypted_tag(workspace_id, &encrypted_tag)
            .await
            .map_err(ServiceError::from)?;

        Ok(result
            .into_iter()
            .map(|s| EncryptedTagItemDto {
                encrypted_tag: s.encrypted_tag,
                count: s.count,
            })
            .collect())
    }
}
