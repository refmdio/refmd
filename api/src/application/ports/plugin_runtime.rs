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

    async fn render_placeholder(
        &self,
        user_id: Option<Uuid>,
        plugin: &str,
        function: &str,
        request: &serde_json::Value,
    ) -> anyhow::Result<Option<serde_json::Value>>;

    async fn permissions(
        &self,
        user_id: Option<Uuid>,
        plugin: &str,
    ) -> anyhow::Result<Option<Vec<String>>>;
}
