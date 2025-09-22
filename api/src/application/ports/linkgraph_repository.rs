use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait LinkGraphRepository: Send + Sync {
    async fn clear_links_for_source(&self, source_id: Uuid) -> anyhow::Result<()>;
    async fn exists_doc_for_owner(&self, doc_id: Uuid, owner_id: Uuid) -> anyhow::Result<bool>;
    async fn find_doc_id_by_owner_and_title(
        &self,
        owner_id: Uuid,
        title: &str,
    ) -> anyhow::Result<Option<Uuid>>;
    async fn upsert_link(
        &self,
        source_id: Uuid,
        target_id: Uuid,
        link_type: &str,
        link_text: Option<String>,
        position_start: i32,
        position_end: i32,
    ) -> anyhow::Result<()>;
}
