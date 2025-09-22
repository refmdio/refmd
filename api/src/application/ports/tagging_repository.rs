use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait TaggingRepository: Send + Sync {
    async fn clear_document_tags(&self, doc_id: Uuid) -> anyhow::Result<()>;
    async fn upsert_tag_return_id(&self, name: &str) -> anyhow::Result<i64>;
    async fn owner_doc_exists(&self, doc_id: Uuid, owner_id: Uuid) -> anyhow::Result<bool>;
    async fn associate_document_tag(&self, doc_id: Uuid, tag_id: i64) -> anyhow::Result<()>;
}
