use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait TagRepository: Send + Sync {
    async fn list_tags(
        &self,
        owner_id: Uuid,
        filter: Option<String>,
    ) -> anyhow::Result<Vec<(String, i64)>>;
}
