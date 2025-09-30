use async_trait::async_trait;
use futures_util::stream::BoxStream;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PersistenceTask {
    pub entry_id: String,
    pub document_id: Uuid,
}

#[async_trait]
pub trait DocPersistencePort: Send + Sync {
    async fn append_update_with_seq(
        &self,
        doc_id: &Uuid,
        seq: i64,
        update: &[u8],
    ) -> anyhow::Result<()>;

    async fn latest_update_seq(&self, doc_id: &Uuid) -> anyhow::Result<Option<i64>>;

    async fn persist_snapshot(
        &self,
        doc_id: &Uuid,
        version: i64,
        snapshot: &[u8],
    ) -> anyhow::Result<()>;

    async fn latest_snapshot_version(&self, doc_id: &Uuid) -> anyhow::Result<Option<i64>>;

    async fn prune_snapshots(&self, doc_id: &Uuid, keep_latest: i64) -> anyhow::Result<()>;

    async fn prune_updates_before(&self, doc_id: &Uuid, seq_inclusive: i64) -> anyhow::Result<()>;

    async fn clear_updates(&self, doc_id: &Uuid) -> anyhow::Result<()>;
}

#[async_trait]
pub trait PersistenceTaskConsumerPort: Send + Sync {
    async fn subscribe_tasks(
        &self,
        start_id: Option<String>,
    ) -> anyhow::Result<BoxStream<'static, anyhow::Result<PersistenceTask>>>;

    async fn ack_task(&self, entry_id: &str) -> anyhow::Result<()>;
}
