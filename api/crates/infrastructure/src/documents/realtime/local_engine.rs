use application::core::ports::errors::PortResult;
use application::documents::ports::realtime::realtime_port::RealtimeEngine;
use application::documents::ports::realtime::realtime_types::{DynRealtimeSink, DynRealtimeStream};
use application::documents::services::realtime::snapshot::doc_from_snapshot_bytes;

pub struct LocalRealtimeEngine {
    pub hub: crate::documents::realtime::Hub,
}

#[async_trait::async_trait]
impl RealtimeEngine for LocalRealtimeEngine {
    async fn subscribe(
        &self,
        doc_id: &str,
        sink: DynRealtimeSink,
        stream: DynRealtimeStream,
        can_edit: bool,
    ) -> PortResult<()> {
        self.hub
            .subscribe(doc_id, sink, stream, can_edit)
            .await
            .map_err(Into::into)
    }

    async fn get_content(&self, doc_id: &str) -> PortResult<Option<String>> {
        self.hub.get_content(doc_id).await.map_err(Into::into)
    }

    async fn force_persist(&self, doc_id: &str) -> PortResult<()> {
        self.hub.force_save_to_fs(doc_id).await.map_err(Into::into)
    }

    async fn apply_snapshot(&self, doc_id: &str, snapshot: &[u8]) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            let doc = doc_from_snapshot_bytes(snapshot)?;
            self.hub.apply_snapshot(doc_id, &doc).await
        }
        .await;
        out.map_err(Into::into)
    }

    async fn set_document_editable(&self, doc_id: &str, editable: bool) -> PortResult<()> {
        self.hub
            .set_document_editable(doc_id, editable)
            .await
            .map_err(Into::into)
    }
}
