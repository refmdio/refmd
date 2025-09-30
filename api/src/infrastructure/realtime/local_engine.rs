use crate::application::ports::realtime_port::RealtimeEngine;
use crate::application::ports::realtime_types::{DynRealtimeSink, DynRealtimeStream};

pub struct LocalRealtimeEngine {
    pub hub: crate::infrastructure::realtime::Hub,
}

#[async_trait::async_trait]
impl RealtimeEngine for LocalRealtimeEngine {
    async fn subscribe(
        &self,
        doc_id: &str,
        sink: DynRealtimeSink,
        stream: DynRealtimeStream,
        can_edit: bool,
    ) -> anyhow::Result<()> {
        self.hub.subscribe(doc_id, sink, stream, can_edit).await
    }

    async fn get_content(&self, doc_id: &str) -> anyhow::Result<Option<String>> {
        self.hub.get_content(doc_id).await
    }

    async fn force_persist(&self, doc_id: &str) -> anyhow::Result<()> {
        self.hub.force_save_to_fs(doc_id).await
    }
}
