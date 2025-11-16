use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait StorageReconcileBackend: Send + Sync {
    async fn list_paths(&self, user_id: Uuid) -> anyhow::Result<Vec<String>>;
}
