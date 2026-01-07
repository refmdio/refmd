use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;
use domain::documents::document::Document;

#[derive(Debug, Clone)]
pub struct WorkspaceTitleAndSlug {
    pub title: String,
    pub workspace_slug: String,
}

#[derive(Debug, Clone)]
pub struct PublishStatusRow {
    pub slug: String,
    pub workspace_slug: String,
}

#[derive(Debug, Clone)]
pub struct PublicDocumentSummaryRow {
    pub id: Uuid,
    pub title: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub published_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
pub trait PublicRepository: Send + Sync {
    async fn ensure_workspace_title_and_slug(
        &self,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> PortResult<Option<WorkspaceTitleAndSlug>>;
    async fn upsert_public_document(&self, doc_id: Uuid, slug: &str) -> PortResult<()>;
    async fn slug_exists(&self, slug: &str) -> PortResult<bool>;
    async fn is_workspace_document(&self, doc_id: Uuid, workspace_id: Uuid) -> PortResult<bool>;
    async fn delete_public_document(&self, doc_id: Uuid) -> PortResult<bool>;
    async fn get_publish_status(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> PortResult<Option<PublishStatusRow>>;
    async fn list_workspace_public_documents(
        &self,
        workspace_slug: &str,
    ) -> PortResult<Vec<PublicDocumentSummaryRow>>;
    async fn get_public_meta_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> PortResult<Option<Document>>;
    async fn public_exists_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> PortResult<bool>;

    /// Store or update plaintext content for a published document (for E2EE mode)
    async fn store_public_content(
        &self,
        doc_id: Uuid,
        title: &str,
        content: &str,
        content_hash: &str,
    ) -> PortResult<()>;

    /// Get stored plaintext content for a published document
    async fn get_public_content(&self, doc_id: Uuid) -> PortResult<Option<PublicContentRow>>;

    /// Delete stored public content when unpublishing
    async fn delete_public_content(&self, doc_id: Uuid) -> PortResult<()>;
}

/// Stored plaintext content for published document
#[derive(Debug, Clone)]
pub struct PublicContentRow {
    pub document_id: Uuid,
    pub title: String,
    pub content: String,
    pub content_hash: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}
