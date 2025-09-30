use async_trait::async_trait;

#[async_trait]
pub trait AwarenessPublisher: Send + Sync {
    async fn publish_awareness(&self, doc_id: &str, frame: Vec<u8>) -> anyhow::Result<()>;
}
