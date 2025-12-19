use async_trait::async_trait;
use futures_util::stream::BoxStream;
use thiserror::Error;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

#[derive(Debug, Error)]
#[error("document_missing")]
pub struct DocumentMissingError {
    pub document_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct PersistenceTask {
    pub entry_id: String,
    pub document_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct SnapshotEntry {
    pub version: i64,
    pub bytes: Vec<u8>,
}

#[async_trait]
pub trait DocPersistencePort: Send + Sync {
    async fn append_update_with_seq(
        &self,
        doc_id: &Uuid,
        seq: i64,
        update: &[u8],
    ) -> PortResult<()>;

    async fn latest_update_seq(&self, doc_id: &Uuid) -> PortResult<Option<i64>>;

    async fn persist_snapshot(
        &self,
        doc_id: &Uuid,
        version: i64,
        snapshot: &[u8],
    ) -> PortResult<()>;

    async fn latest_snapshot_entry(&self, doc_id: &Uuid) -> PortResult<Option<SnapshotEntry>>;

    async fn latest_snapshot_version(&self, doc_id: &Uuid) -> PortResult<Option<i64>>;

    async fn prune_snapshots(&self, doc_id: &Uuid, keep_latest: i64) -> PortResult<()>;

    async fn prune_updates_before(&self, doc_id: &Uuid, seq_inclusive: i64) -> PortResult<()>;

    async fn clear_updates(&self, doc_id: &Uuid) -> PortResult<()>;
}

#[async_trait]
pub trait PersistenceTaskConsumerPort: Send + Sync {
    async fn subscribe_tasks(
        &self,
        start_id: Option<String>,
    ) -> PortResult<BoxStream<'static, PortResult<PersistenceTask>>>;

    async fn ack_task(&self, entry_id: &str) -> PortResult<()>;
}
