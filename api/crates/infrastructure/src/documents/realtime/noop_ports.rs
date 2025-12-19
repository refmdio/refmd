use async_trait::async_trait;

use application::core::ports::errors::PortResult;
use application::documents::ports::realtime::awareness_port::AwarenessPublisher;
use application::documents::ports::realtime::realtime_hydration_port::{
    RealtimeBacklogReader, StreamFrame,
};

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
    ) -> PortResult<Vec<StreamFrame>> {
        Ok(Vec::new())
    }

    async fn read_awareness_backlog(
        &self,
        _doc_id: &str,
        _last_stream_id: Option<&str>,
    ) -> PortResult<Vec<StreamFrame>> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl AwarenessPublisher for NoopAwarenessPublisher {
    async fn publish_awareness(&self, _doc_id: &str, _frame: Vec<u8>) -> PortResult<()> {
        Ok(())
    }
}
