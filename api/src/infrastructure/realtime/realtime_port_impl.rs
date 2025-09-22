use crate::application::ports::realtime_port::RealtimePort;

pub struct HubRealtimePort {
    pub hub: crate::infrastructure::realtime::Hub,
}

#[async_trait::async_trait]
impl RealtimePort for HubRealtimePort {
    async fn get_content(&self, doc_id: &str) -> anyhow::Result<Option<String>> {
        self.hub.get_content(doc_id).await
    }

    async fn force_save_to_fs(&self, doc_id: &str) -> anyhow::Result<()> {
        self.hub.force_save_to_fs(doc_id).await
    }
}
