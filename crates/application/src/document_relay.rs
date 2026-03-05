//! Document relay bus traits for cross-instance message delivery
//!
//! In cluster mode, WebSocket messages (updates, snapshots, ephemeral) must be
//! relayed across backend instances via Redis Pub/Sub. These traits define the
//! publishing and subscribing contracts. Implementations live in the infrastructure layer.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use uuid::Uuid;

/// Typed payload carried by relay events on the broadcast channel.
///
/// Follows the established event bus pattern (DeviceEvent, WorkspaceEvent):
/// broadcast channels carry strongly-typed payloads, not serialized strings.
/// Routing is determined by enum variant, not a separate channel-kind field.
#[derive(Debug, Clone)]
pub enum DocumentRelayEventPayload {
    /// Update or snapshot message from `doc:{document_id}` channel
    Document(RelayPayload),
    /// Ephemeral message (cursor/presence) from `ephemeral:{document_id}` channel
    Ephemeral(EphemeralRelayPayload),
}

/// Event received from the document relay bus
#[derive(Debug, Clone)]
pub struct DocumentRelayEvent {
    /// Document this message belongs to
    pub document_id: Uuid,
    /// Typed payload (routing by variant, not separate channel-kind field)
    pub payload: DocumentRelayEventPayload,
}

/// Relay payload published by application-layer handlers after persist.
///
/// Uses application-layer types (base64url strings, serde_json::Value) —
/// no dependency on presentation-layer WsOutMessage.
/// Wire-format payload for document update relay messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayUpdatePayload {
    pub ciphertext: String,
    pub nonce: String,
    pub signature: String,
    pub public_data: serde_json::Value,
    pub version: i64,
}

/// Wire-format payload for document snapshot relay messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelaySnapshotPayload {
    pub snapshot_id: String,
    pub ciphertext: String,
    pub nonce: String,
    pub signature: String,
    pub public_data: serde_json::Value,
}

/// Typed relay payload carried by broadcast channel events.
///
/// Deserialized by field structure (not by the outer `type` metadata field).
/// `type` is for observability only; routing uses channel name
/// (design: websocket-scaling.md L112).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum RelayPayload {
    Update(RelayUpdatePayload),
    Snapshot(RelaySnapshotPayload),
}

/// Ephemeral relay payload (cursor/presence).
///
/// Typed DTO for ephemeral messages relayed across backend instances.
/// Ephemeral messages have no application-layer handler; published directly
/// from presentation layer via this typed contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EphemeralRelayPayload {
    pub ciphertext: String,
    pub nonce: String,
    pub signature: String,
    pub public_data: serde_json::Value,
}

/// Trait for publishing document messages to other backend instances.
///
/// All methods are synchronous (non-blocking channel enqueue via `try_send`).
/// This is enforced at the type level to prevent implementations from blocking
/// the caller, which would delay local ack/broadcast
/// (design: websocket-scaling.md, relay publish section).
pub trait DocumentRelayPublisher: Send + Sync {
    /// Publish a document relay payload (update/snapshot) to other instances.
    /// Called by application-layer handlers after successful persist.
    fn publish_document_relay(&self, document_id: Uuid, payload: &RelayPayload);

    /// Publish an ephemeral message (cursor/presence) to other instances.
    /// Ephemeral messages have no application-layer handler; published directly
    /// from presentation layer via typed payload.
    fn publish_ephemeral_relay(&self, document_id: Uuid, payload: &EphemeralRelayPayload);
}

/// Trait for subscribing to document relay events from other instances.
///
/// Manages per-document channel subscriptions: each backend subscribes only
/// to channels for documents with active local WebSocket connections.
/// Subscribe is async (awaits Redis SUBSCRIBE confirmation or timeout);
/// unsubscribe is synchronous fire-and-forget (enqueues command without awaiting).
/// (design: websocket-scaling.md §Subscribe管理).
#[async_trait]
pub trait DocumentRelaySubscriber: Send + Sync {
    /// Subscribe to relay events (returns a broadcast receiver).
    fn subscribe(&self) -> broadcast::Receiver<DocumentRelayEvent>;

    /// Subscribe to relay bus reconnection events.
    /// After the relay bus recovers from an outage (e.g., Redis reconnect),
    /// connected clients may have missed cross-node updates.
    /// Listeners should trigger PostgreSQL resync for affected clients
    /// (design: websocket-scaling.md §Redis接続断, point 3).
    fn subscribe_reconnect(&self) -> broadcast::Receiver<()>;

    /// Increment the relay subscription refcount for a document.
    /// Called on every connection join. The implementation refcounts internally
    /// and only sends the actual Redis SUBSCRIBE on the first call (refcount 0→1).
    /// Awaits until Redis SUBSCRIBE is confirmed (or times out in degraded mode).
    async fn subscribe_document(&self, document_id: Uuid);

    /// Stop subscribing to a document's relay channels.
    /// Decrements refcount and enqueues the Redis UNSUBSCRIBE command without
    /// awaiting confirmation. The implementation maintains a per-document refcount
    /// and only sends the actual Redis UNSUBSCRIBE when the count reaches zero.
    /// Called on every connection removal.
    fn unsubscribe_document(&self, document_id: Uuid);
}

/// Combined publish + subscribe trait for convenience.
pub trait DocumentRelayBus: DocumentRelayPublisher + DocumentRelaySubscriber + Send + Sync {}

impl<T: DocumentRelayPublisher + DocumentRelaySubscriber + Send + Sync> DocumentRelayBus for T {}
