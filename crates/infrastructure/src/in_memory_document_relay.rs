//! In-memory document relay bus for single-node deployments
//!
//! No cross-instance relay is needed in single-node mode.
//! Publish is a no-op; subscribe returns an empty channel.

use application::document_relay::{
    DocumentRelayEvent, DocumentRelayPublisher, DocumentRelaySubscriber, EphemeralRelayPayload,
    RelayPayload,
};
use async_trait::async_trait;
use tokio::sync::broadcast;

/// In-memory document relay bus (no-op for single-node deployments)
#[derive(Clone)]
pub struct InMemoryDocumentRelayBus {
    sender: broadcast::Sender<DocumentRelayEvent>,
    /// Reconnect channel (never fires in single-node mode, but provides
    /// a valid receiver to callers without temporary-channel hacks).
    reconnect_sender: broadcast::Sender<()>,
}

impl Default for InMemoryDocumentRelayBus {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryDocumentRelayBus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(16);
        let (reconnect_sender, _) = broadcast::channel(1);
        Self { sender, reconnect_sender }
    }
}

impl DocumentRelayPublisher for InMemoryDocumentRelayBus {
    fn publish_document_relay(&self, _document_id: uuid::Uuid, _payload: &RelayPayload) {
        // No-op: single-node mode, local broadcast_except already delivered
    }

    fn publish_ephemeral_relay(&self, _document_id: uuid::Uuid, _payload: &EphemeralRelayPayload) {
        // No-op: single-node mode, local broadcast_except already delivered
    }
}

#[async_trait]
impl DocumentRelaySubscriber for InMemoryDocumentRelayBus {
    fn subscribe(&self) -> broadcast::Receiver<DocumentRelayEvent> {
        self.sender.subscribe()
    }

    fn subscribe_reconnect(&self) -> broadcast::Receiver<()> {
        // Single-node mode: Redis reconnect never happens, but return a valid receiver.
        self.reconnect_sender.subscribe()
    }

    async fn subscribe_document(&self, _document_id: uuid::Uuid) {
        // No-op: single-node mode, no Redis channels to subscribe
    }

    fn unsubscribe_document(&self, _document_id: uuid::Uuid) {
        // No-op: single-node mode, no Redis channels to unsubscribe
    }
}
