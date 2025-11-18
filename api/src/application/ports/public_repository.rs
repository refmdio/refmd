use async_trait::async_trait;
use uuid::Uuid;

use crate::domain::documents::document::Document;

#[async_trait]
pub trait PublicRepository: Send + Sync {
    async fn ensure_workspace_title_and_slug(
        &self,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<(String, String)>>; // (title, workspace_slug)
    async fn upsert_public_document(&self, doc_id: Uuid, slug: &str) -> anyhow::Result<()>;
    async fn slug_exists(&self, slug: &str) -> anyhow::Result<bool>;
    async fn is_workspace_document(&self, doc_id: Uuid, workspace_id: Uuid)
    -> anyhow::Result<bool>;
    async fn delete_public_document(&self, doc_id: Uuid) -> anyhow::Result<bool>;
    async fn get_publish_status(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> anyhow::Result<Option<(String, String)>>; // (slug, workspace_slug)
    async fn list_workspace_public_documents(
        &self,
        workspace_slug: &str,
    ) -> anyhow::Result<
        Vec<(
            Uuid,
            String,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        )>,
    >;
    async fn get_public_meta_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> anyhow::Result<Option<Document>>;
    async fn public_exists_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> anyhow::Result<bool>;
}
