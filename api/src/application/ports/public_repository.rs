use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait PublicRepository: Send + Sync {
    async fn ensure_ownership_and_owner_name(
        &self,
        doc_id: Uuid,
        owner_id: Uuid,
    ) -> anyhow::Result<Option<(String, String)>>; // (title, owner_name)
    async fn upsert_public_document(&self, doc_id: Uuid, slug: &str) -> anyhow::Result<()>;
    async fn slug_exists(&self, slug: &str) -> anyhow::Result<bool>;
    async fn is_owner_document(&self, doc_id: Uuid, owner_id: Uuid) -> anyhow::Result<bool>;
    async fn delete_public_document(&self, doc_id: Uuid) -> anyhow::Result<bool>;
    async fn get_publish_status(
        &self,
        owner_id: Uuid,
        doc_id: Uuid,
    ) -> anyhow::Result<Option<(String, String)>>; // (slug, owner_name)
    async fn list_user_public_documents(
        &self,
        owner_name: &str,
    ) -> anyhow::Result<
        Vec<(
            Uuid,
            String,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        )>,
    >;
    async fn get_public_meta_by_owner_and_id(
        &self,
        owner_name: &str,
        doc_id: Uuid,
    ) -> anyhow::Result<
        Option<(
            Uuid,
            String,
            Option<Uuid>,
            String,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
            Option<String>,
        )>,
    >;
    async fn public_exists_by_owner_and_id(
        &self,
        owner_name: &str,
        doc_id: Uuid,
    ) -> anyhow::Result<bool>;
}
