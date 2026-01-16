use std::sync::Arc;

use uuid::Uuid;

use crate::core::ports::storage::storage_port::StorageResolverPort;
use crate::core::services::errors::ServiceError;
use crate::documents::dtos::PublicDocumentSummaryDto;
use crate::documents::ports::publishing::public_repository::{
    PublicFileRow, PublicRepository, StorePublicFileInput,
};
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
    storage: Arc<dyn StorageResolverPort>,
}

#[async_trait]
pub trait PublicServiceFacade: Send + Sync {
    /// Publish document.
    /// For E2EE mode: pass plaintext_title and plaintext_content
    /// For non-E2EE mode: pass None for both
    /// noindex: if true, adds noindex meta tag to prevent search engine indexing (default: true)
    async fn publish_document(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
        plaintext_title: Option<&str>,
        plaintext_content: Option<&str>,
        noindex: bool,
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

    /// Update noindex setting for a published document
    async fn update_noindex(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
        noindex: bool,
    ) -> Result<bool, ServiceError>;

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
    ) -> Result<(String, bool), ServiceError>;

    // --- Public file methods ---

    /// Store a decrypted file for public access
    async fn store_public_file(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
        file_id: Uuid,
        original_filename: &str,
        logical_filename: &str,
        mime_type: &str,
        bytes: &[u8],
    ) -> Result<(), ServiceError>;

    /// Get list of public files for a document
    async fn get_public_files(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> Result<Vec<PublicFileRow>, ServiceError>;

    /// Read public file bytes by file_id
    async fn read_public_file(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
        file_id: Uuid,
    ) -> Result<(Vec<u8>, PublicFileRow), ServiceError>;

    /// Read public file bytes by logical filename
    async fn read_public_file_by_logical_filename(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
        logical_filename: &str,
    ) -> Result<(Vec<u8>, PublicFileRow), ServiceError>;
}

#[async_trait]
impl PublicServiceFacade for PublicService {
    async fn publish_document(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
        plaintext_title: Option<&str>,
        plaintext_content: Option<&str>,
        noindex: bool,
    ) -> Result<PublishResponseDto, ServiceError> {
        self.publish_document(workspace_id, permissions, doc_id, plaintext_title, plaintext_content, noindex)
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

    async fn update_noindex(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
        noindex: bool,
    ) -> Result<bool, ServiceError> {
        self.update_noindex(workspace_id, permissions, doc_id, noindex)
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
    ) -> Result<(String, bool), ServiceError> {
        self.get_public_content_by_workspace_and_id(workspace_slug, doc_id)
            .await
    }

    async fn store_public_file(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
        file_id: Uuid,
        original_filename: &str,
        logical_filename: &str,
        mime_type: &str,
        bytes: &[u8],
    ) -> Result<(), ServiceError> {
        self.store_public_file(
            workspace_id,
            permissions,
            doc_id,
            file_id,
            original_filename,
            logical_filename,
            mime_type,
            bytes,
        )
        .await
    }

    async fn get_public_files(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> Result<Vec<PublicFileRow>, ServiceError> {
        self.get_public_files(workspace_slug, doc_id).await
    }

    async fn read_public_file(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
        file_id: Uuid,
    ) -> Result<(Vec<u8>, PublicFileRow), ServiceError> {
        self.read_public_file(workspace_slug, doc_id, file_id).await
    }

    async fn read_public_file_by_logical_filename(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
        logical_filename: &str,
    ) -> Result<(Vec<u8>, PublicFileRow), ServiceError> {
        self.read_public_file_by_logical_filename(workspace_slug, doc_id, logical_filename)
            .await
    }
}

impl PublicService {
    pub fn new(
        repo: Arc<dyn PublicRepository>,
        realtime: Arc<dyn RealtimeEngine>,
        storage: Arc<dyn StorageResolverPort>,
    ) -> Self {
        Self {
            repo,
            realtime,
            storage,
        }
    }

    /// Publish document.
    /// For E2EE mode: pass plaintext_title and plaintext_content
    /// For non-E2EE mode: pass None for both
    /// noindex: if true, adds noindex meta tag to prevent search engine indexing (default: true)
    pub async fn publish_document(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
        plaintext_title: Option<&str>,
        plaintext_content: Option<&str>,
        noindex: bool,
    ) -> Result<PublishResponseDto, ServiceError> {
        public_policy::ensure_public_publish_allowed(permissions)
            .map_err(|_| ServiceError::Forbidden)?;

        let uc = PublishDocument {
            repo: self.repo.as_ref(),
        };
        let publish_result = uc
            .execute(workspace_id, doc_id, noindex)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;

        // For E2EE mode: store plaintext content for public access
        if let (Some(title), Some(content)) = (plaintext_title, plaintext_content) {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(title);
            hasher.update(content);
            let content_hash = hex::encode(hasher.finalize());

            self.repo
                .store_public_content(doc_id, title, content, &content_hash)
                .await
                .map_err(ServiceError::from)?;
        }

        Ok(publish_result)
    }

    pub async fn unpublish_document(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<bool, ServiceError> {
        public_policy::ensure_public_unpublish_allowed(permissions)
            .map_err(|_| ServiceError::Forbidden)?;

        // Delete stored public content (E2EE mode)
        self.repo
            .delete_public_content(doc_id)
            .await
            .map_err(ServiceError::from)?;

        // Delete public files from storage
        self.storage
            .delete_public_files_for_document(workspace_id, doc_id)
            .await
            .map_err(ServiceError::from)?;

        // Delete public file metadata from database
        self.repo
            .delete_public_files(doc_id)
            .await
            .map_err(ServiceError::from)?;

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
            noindex: status.noindex,
        })
    }

    pub async fn update_noindex(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
        noindex: bool,
    ) -> Result<bool, ServiceError> {
        public_policy::ensure_public_publish_allowed(permissions)
            .map_err(|_| ServiceError::Forbidden)?;

        // Verify document belongs to workspace
        let is_workspace_doc = self
            .repo
            .is_workspace_document(doc_id, workspace_id)
            .await
            .map_err(ServiceError::from)?;
        if !is_workspace_doc {
            return Err(ServiceError::NotFound);
        }

        self.repo
            .update_noindex(doc_id, noindex)
            .await
            .map_err(ServiceError::from)
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
    ) -> Result<(String, bool), ServiceError> {
        // Get noindex setting (also verifies document is published)
        let noindex = self
            .repo
            .get_noindex_by_workspace_and_id(workspace_slug, doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;

        // Prefer stored plaintext content (E2EE mode) over realtime
        if let Some(stored) = self
            .repo
            .get_public_content(doc_id)
            .await
            .map_err(ServiceError::from)?
        {
            return Ok((stored.content, noindex));
        }

        // Fall back to realtime content for non-E2EE documents
        let content = self
            .realtime
            .get_content(&doc_id.to_string())
            .await
            .map_err(ServiceError::from)?
            .unwrap_or_default();
        Ok((content, noindex))
    }

    // --- Public file methods ---

    pub async fn store_public_file(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
        file_id: Uuid,
        original_filename: &str,
        logical_filename: &str,
        mime_type: &str,
        bytes: &[u8],
    ) -> Result<(), ServiceError> {
        // Verify permission to publish
        public_policy::ensure_public_publish_allowed(permissions)
            .map_err(|_| ServiceError::Forbidden)?;

        // Verify document belongs to workspace
        let is_workspace_doc = self
            .repo
            .is_workspace_document(doc_id, workspace_id)
            .await
            .map_err(ServiceError::from)?;
        if !is_workspace_doc {
            return Err(ServiceError::NotFound);
        }

        // Store the file in storage
        let storage_path = self
            .storage
            .store_public_file(workspace_id, doc_id, file_id, bytes)
            .await
            .map_err(ServiceError::from)?;

        // Calculate content hash
        use sha2::{Digest, Sha256};
        let content_hash = hex::encode(Sha256::digest(bytes));

        // Store metadata in database
        self.repo
            .store_public_file(StorePublicFileInput {
                document_id: doc_id,
                workspace_id,
                file_id,
                original_filename: original_filename.to_string(),
                logical_filename: logical_filename.to_string(),
                mime_type: mime_type.to_string(),
                size: bytes.len() as i64,
                storage_path,
                content_hash,
            })
            .await
            .map_err(ServiceError::from)?;

        Ok(())
    }

    pub async fn get_public_files(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> Result<Vec<PublicFileRow>, ServiceError> {
        // Verify document is published
        let exists = self
            .repo
            .public_exists_by_workspace_and_id(workspace_slug, doc_id)
            .await
            .map_err(ServiceError::from)?;
        if !exists {
            return Err(ServiceError::NotFound);
        }

        self.repo
            .get_public_files(doc_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn read_public_file(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
        file_id: Uuid,
    ) -> Result<(Vec<u8>, PublicFileRow), ServiceError> {
        // Verify document is published
        let exists = self
            .repo
            .public_exists_by_workspace_and_id(workspace_slug, doc_id)
            .await
            .map_err(ServiceError::from)?;
        if !exists {
            return Err(ServiceError::NotFound);
        }

        // Get file metadata
        let file = self
            .repo
            .get_public_file(doc_id, file_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;

        // Read file bytes
        let bytes = self
            .storage
            .read_public_file(file.workspace_id, doc_id, file_id)
            .await
            .map_err(ServiceError::from)?;

        Ok((bytes, file))
    }

    pub async fn read_public_file_by_logical_filename(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
        logical_filename: &str,
    ) -> Result<(Vec<u8>, PublicFileRow), ServiceError> {
        // Verify document is published
        let exists = self
            .repo
            .public_exists_by_workspace_and_id(workspace_slug, doc_id)
            .await
            .map_err(ServiceError::from)?;
        if !exists {
            return Err(ServiceError::NotFound);
        }

        // Get file metadata by logical filename
        let file = self
            .repo
            .get_public_file_by_logical_filename(doc_id, logical_filename)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;

        // Read file bytes
        let bytes = self
            .storage
            .read_public_file(file.workspace_id, doc_id, file.file_id)
            .await
            .map_err(ServiceError::from)?;

        Ok((bytes, file))
    }
}
