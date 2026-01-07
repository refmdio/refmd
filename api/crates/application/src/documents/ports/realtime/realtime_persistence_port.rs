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
    pub nonce: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
}

/// Encryption metadata for E2EE content
#[derive(Debug, Clone, Default)]
pub struct ContentEncryptionMeta {
    pub nonce: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
}

/// Encrypted update data for E2EE documents
#[derive(Debug, Clone)]
pub struct EncryptedUpdateData {
    pub data: Vec<u8>,
    pub nonce: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
}

#[async_trait]
pub trait DocPersistencePort: Send + Sync {
    async fn append_update_with_seq(
        &self,
        doc_id: &Uuid,
        seq: i64,
        update: &[u8],
    ) -> PortResult<()>;

    /// Append encrypted update with E2EE metadata
    async fn append_encrypted_update_with_seq(
        &self,
        doc_id: &Uuid,
        seq: i64,
        update: &EncryptedUpdateData,
    ) -> PortResult<()>;

    async fn latest_update_seq(&self, doc_id: &Uuid) -> PortResult<Option<i64>>;

    async fn persist_snapshot(
        &self,
        doc_id: &Uuid,
        version: i64,
        snapshot: &[u8],
        encryption_meta: Option<&ContentEncryptionMeta>,
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
