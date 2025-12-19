use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

#[async_trait]
pub trait StorageReconcileBackend: Send + Sync {
    async fn list_paths(&self, user_id: Uuid) -> PortResult<Vec<String>>;
}
