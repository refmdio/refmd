use async_trait::async_trait;

use crate::application::ports::awareness_port::AwarenessPublisher;
use crate::application::ports::realtime_hydration_port::{RealtimeBacklogReader, StreamFrame};

#[derive(Debug, Clone, Default)]
pub struct NoopBacklogReader;

#[derive(Debug, Clone, Default)]
pub struct NoopAwarenessPublisher;

#[async_trait]
impl RealtimeBacklogReader for NoopBacklogReader {
    async fn read_update_backlog(
        &self,
        _doc_id: &str,
        _last_stream_id: Option<&str>,
    ) -> anyhow::Result<Vec<StreamFrame>> {
        Ok(Vec::new())
    }

    async fn read_awareness_backlog(
        &self,
        _doc_id: &str,
        _last_stream_id: Option<&str>,
    ) -> anyhow::Result<Vec<StreamFrame>> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl AwarenessPublisher for NoopAwarenessPublisher {
    async fn publish_awareness(&self, _doc_id: &str, _frame: Vec<u8>) -> anyhow::Result<()> {
        Ok(())
    }
}
