use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait AccessRepository: Send + Sync {
    async fn user_owns_document(&self, doc_id: Uuid, user_id: Uuid) -> anyhow::Result<bool>;
    async fn is_document_public(&self, doc_id: Uuid) -> anyhow::Result<bool>;
}
