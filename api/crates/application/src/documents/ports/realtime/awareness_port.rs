use async_trait::async_trait;

use crate::core::ports::errors::PortResult;

#[async_trait]
pub trait AwarenessPublisher: Send + Sync {
    async fn publish_awareness(&self, doc_id: &str, frame: Vec<u8>) -> PortResult<()>;
}
