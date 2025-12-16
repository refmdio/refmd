use application::ports::realtime_port::RealtimeEngine;
use application::ports::realtime_types::{DynRealtimeSink, DynRealtimeStream};
use application::services::realtime::snapshot::doc_from_snapshot_bytes;

pub struct LocalRealtimeEngine {
    pub hub: crate::realtime::Hub,
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

    async fn apply_snapshot(&self, doc_id: &str, snapshot: &[u8]) -> anyhow::Result<()> {
        let doc = doc_from_snapshot_bytes(snapshot)?;
        self.hub.apply_snapshot(doc_id, &doc).await
    }

    async fn set_document_editable(&self, doc_id: &str, editable: bool) -> anyhow::Result<()> {
        self.hub.set_document_editable(doc_id, editable).await
    }
}
