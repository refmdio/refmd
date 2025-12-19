use async_trait::async_trait;
use serde_json::Value;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

#[derive(Debug, Clone)]
pub struct PluginScopedEvent {
    pub user_id: Option<Uuid>,
    pub workspace_id: Option<Uuid>,
    pub payload: Value,
}

#[async_trait]
pub trait PluginEventPublisher: Send + Sync {
    async fn publish(&self, event: &PluginScopedEvent) -> PortResult<()>;
}
