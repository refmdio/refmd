use async_trait::async_trait;
use std::fmt;

use crate::core::ports::errors::PortResult;

#[derive(Debug)]
pub struct RealtimeError(Box<dyn std::error::Error + Send + Sync + 'static>);

impl RealtimeError {
    pub fn new<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self(Box::new(err))
    }
}

impl fmt::Display for RealtimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for RealtimeError {}

use super::realtime_types::{DynRealtimeSink, DynRealtimeStream};

#[async_trait]
pub trait RealtimeEngine: Send + Sync {
    async fn subscribe(
        &self,
        doc_id: &str,
        sink: DynRealtimeSink,
        stream: DynRealtimeStream,
        can_edit: bool,
    ) -> PortResult<()>;

    async fn get_content(&self, doc_id: &str) -> PortResult<Option<String>>;

    /// Get Yjs snapshot with E2EE metadata (nonce, signature)
    /// Returns snapshot data including nonce for decryption
    async fn get_snapshot(&self, doc_id: &str) -> PortResult<Option<SnapshotData>>;

    async fn force_persist(&self, doc_id: &str) -> PortResult<()>;

    async fn force_save_to_fs(&self, doc_id: &str) -> PortResult<()> {
        self.force_persist(doc_id).await
    }

    async fn apply_snapshot(&self, doc_id: &str, snapshot: &[u8]) -> PortResult<()>;

    /// Apply encrypted snapshot with E2EE metadata
    async fn apply_encrypted_snapshot(
        &self,
        doc_id: &str,
        snapshot: &[u8],
        _nonce: Option<&[u8]>,
        _signature: Option<&[u8]>,
    ) -> PortResult<()> {
        // Default implementation ignores encryption metadata
        self.apply_snapshot(doc_id, snapshot).await
    }

    /// Apply encrypted updates (delta) for E2EE documents
    /// This appends encrypted Yjs updates without processing them
    async fn apply_encrypted_updates(
        &self,
        doc_id: &str,
        updates: &[EncryptedUpdate],
    ) -> PortResult<()>;

    async fn set_document_editable(&self, _doc_id: &str, _editable: bool) -> PortResult<()> {
        Ok(())
    }
}

/// Encrypted Yjs update for E2EE documents
#[derive(Debug, Clone)]
pub struct EncryptedUpdate {
    pub data: Vec<u8>,
    pub nonce: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
}

/// Snapshot data with E2EE metadata
#[derive(Debug, Clone)]
pub struct SnapshotData {
    /// Yjs snapshot bytes
    pub data: Vec<u8>,
    /// Nonce for decryption
    pub nonce: Option<Vec<u8>>,
    /// Signature for verification
    pub signature: Option<Vec<u8>>,
}
