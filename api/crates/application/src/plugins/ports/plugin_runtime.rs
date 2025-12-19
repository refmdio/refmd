use async_trait::async_trait;

use crate::plugins::dtos::ExecResult;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

#[async_trait]
pub trait PluginRuntime: Send + Sync {
    async fn execute(
        &self,
        user_id: Option<Uuid>,
        plugin: &str,
        action: &str,
        payload: &serde_json::Value,
    ) -> PortResult<Option<ExecResult>>;

    async fn render_placeholder(
        &self,
        user_id: Option<Uuid>,
        plugin: &str,
        function: &str,
        request: &serde_json::Value,
    ) -> PortResult<Option<serde_json::Value>>;

    async fn permissions(
        &self,
        user_id: Option<Uuid>,
        plugin: &str,
    ) -> PortResult<Option<Vec<String>>>;
}
