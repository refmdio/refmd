use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait ShareAccessPort: Send + Sync {
    async fn resolve_share_by_token(
        &self,
        token: &str,
    ) -> anyhow::Result<
        Option<(
            Uuid,
            String,
            Option<chrono::DateTime<chrono::Utc>>,
            Uuid,
            String,
        )>,
    >;

    async fn get_materialized_permission(
        &self,
        parent_share_id: Uuid,
        doc_id: Uuid,
    ) -> anyhow::Result<Option<String>>;
}
