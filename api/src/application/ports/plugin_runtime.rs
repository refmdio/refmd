use async_trait::async_trait;

use crate::application::dto::plugins::ExecResult;
use uuid::Uuid;

#[async_trait]
pub trait PluginRuntime: Send + Sync {
    async fn execute(
        &self,
        user_id: Option<Uuid>,
        plugin: &str,
        action: &str,
        payload: &serde_json::Value,
    ) -> anyhow::Result<Option<ExecResult>>;
}
