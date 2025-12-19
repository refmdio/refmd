use async_trait::async_trait;
use serde_json::Value;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

#[async_trait]
pub trait DocEventLog: Send + Sync {
    async fn append(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        event_type: &str,
        payload: Option<Value>,
    ) -> PortResult<()>;
}
