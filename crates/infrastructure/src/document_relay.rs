//! Redis Pub/Sub document relay bus for HA mode
//!
//! Relays document messages (updates, snapshots, ephemeral) across backend
//! instances via Redis Pub/Sub. Each backend subscribes only to channels for
//! documents with active local WebSocket connections (per-document subscribe).

use application::document_relay::{
    DocumentRelayEvent, DocumentRelayEventPayload, DocumentRelayPublisher,
    DocumentRelaySubscriber, EphemeralRelayPayload, RelayPayload,
};
use async_trait::async_trait;
use futures::StreamExt;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, oneshot, Notify, Semaphore};
use uuid::Uuid;

use crate::RedisPool;

/// Redis message format matching the design doc (websocket-scaling.md, channel design).
///
/// For `doc:{id}` channels, `data` is a `RelayPayload` (application-layer DTO).
/// For `ephemeral:{id}` channels, `data` is an `EphemeralRelayPayload` (application-layer DTO).
///
/// ```json
/// {
///   "type": "snapshot" | "update" | "ephemeral-message",
///   "data": <RelayPayload or EphemeralRelayPayload JSON>,
///   "origin_backend": "backend-1"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RedisRelayMessage {
    /// Message type (e.g., "update", "snapshot", "ephemeral-message")
    #[serde(rename = "type")]
    message_type: String,
    /// Payload JSON value (RelayPayload for doc channels, EphemeralRelayPayload for ephemeral)
    data: serde_json::Value,
    /// Origin backend instance ID for deduplication
    origin_backend: String,
}

/// Commands sent to the subscription loop for per-document channel management.
enum SubscribeCommand {
    /// Subscribe to doc/ephemeral channels. Carries oneshot for ack.
    Subscribe(Uuid, oneshot::Sender<()>),
    /// Unsubscribe (fire-and-forget, no ack).
    Unsubscribe(Uuid),
}

/// Command sent to the publish worker via bounded channel.
struct PublishCommand {
    channel: String,
    serialized: String,
}

/// Redis Pub/Sub document relay bus for cluster deployments
///
/// Publishes document messages to Redis and subscribes to receive messages
/// from other instances. Uses per-document channels (`doc:{id}`, `ephemeral:{id}`)
/// with dynamic subscribe/unsubscribe as rooms are created/destroyed.
/// Per-document subscription state for refcounting and subscribe-in-progress tracking.
struct DocSubscriptionState {
    /// Number of active connections for this document on this instance.
    refcount: usize,
    /// Notifies waiters when the initial Redis SUBSCRIBE completes.
    /// Set when subscribe is in-progress, cleared after completion.
    subscribe_notify: Option<Arc<Notify>>,
}

pub struct RedisDocumentRelayBus {
    redis: RedisPool,
    redis_url: String,
    local_sender: broadcast::Sender<DocumentRelayEvent>,
    /// Notifies listeners when the relay bus reconnects after an outage.
    /// Listeners should trigger PostgreSQL resync for connected clients
    /// (design: websocket-scaling.md §Redis接続断, point 3).
    reconnect_sender: broadcast::Sender<()>,
    /// Unique identifier for this instance (to avoid self-delivery from Redis)
    instance_id: String,
    /// Channel for sending subscribe/unsubscribe commands to the subscription loop
    subscribe_tx: mpsc::UnboundedSender<SubscribeCommand>,
    /// Bounded channel for enqueuing publish commands to the worker task.
    /// Callers use `try_send` (non-blocking): if the channel buffer is full
    /// (all semaphore permits in use AND buffer exhausted), the message is
    /// dropped (accepted risk: recovered via client delta reconnect).
    publish_tx: mpsc::Sender<PublishCommand>,
    /// Per-document subscription state: refcount + in-progress tracking.
    /// Only documents with refcount > 0 are subscribed to Redis channels.
    doc_states: Arc<std::sync::Mutex<HashMap<Uuid, DocSubscriptionState>>>,
}

impl Clone for RedisDocumentRelayBus {
    fn clone(&self) -> Self {
        Self {
            redis: self.redis.clone(),
            redis_url: self.redis_url.clone(),
            local_sender: self.local_sender.clone(),
            reconnect_sender: self.reconnect_sender.clone(),
            instance_id: self.instance_id.clone(),
            subscribe_tx: self.subscribe_tx.clone(),
            publish_tx: self.publish_tx.clone(),
            doc_states: self.doc_states.clone(),
        }
    }
}

impl RedisDocumentRelayBus {
    /// Create a new Redis document relay bus and start the subscription listener.
    pub fn new(redis: RedisPool, redis_url: String) -> Arc<Self> {
        let (local_sender, _) = broadcast::channel(256);
        let (reconnect_sender, _) = broadcast::channel(16);
        let (subscribe_tx, subscribe_rx) = mpsc::unbounded_channel();
        let (publish_tx, publish_rx) = mpsc::channel(PUBLISH_CHANNEL_BUFFER);
        let instance_id = std::env::var("CLUSTER_BACKEND_ID")
            .unwrap_or_else(|_| Uuid::new_v4().to_string());

        tracing::info!("RedisDocumentRelayBus instance_id: {}", instance_id);

        let bus = Arc::new(Self {
            redis: redis.clone(),
            redis_url,
            local_sender,
            reconnect_sender,
            instance_id,
            subscribe_tx,
            publish_tx,
            doc_states: Arc::new(std::sync::Mutex::new(HashMap::new())),
        });

        let bus_clone = Arc::clone(&bus);
        tokio::spawn(async move {
            bus_clone.subscription_loop(subscribe_rx).await;
        });

        // Publish worker: drains the bounded channel, acquires a semaphore permit
        // (blocking the worker, not the caller), then spawns an independent task
        // per message with its own timeout. This gives:
        // - Non-blocking callers (try_send into channel buffer)
        // - Buffering under transient back-pressure (channel absorbs spikes)
        // - Bounded concurrency (semaphore caps in-flight Redis publishes)
        // - Independent per-message timeouts (no head-of-line blocking)
        let publish_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_PUBLISHES));
        tokio::spawn(Self::publish_worker(redis, publish_rx, publish_semaphore));

        bus
    }

    /// Background worker that drains the publish channel and dispatches each
    /// message to Redis with bounded concurrency via semaphore.
    async fn publish_worker(
        redis: RedisPool,
        mut publish_rx: mpsc::Receiver<PublishCommand>,
        semaphore: Arc<Semaphore>,
    ) {
        while let Some(cmd) = publish_rx.recv().await {
            // Acquire a permit (blocks worker, not the original caller).
            // Under normal Redis (~1ms), permits return almost immediately.
            // Under degraded Redis, the worker blocks here while the channel
            // buffer absorbs new messages from callers.
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break, // Semaphore closed (bus dropped)
            };
            let redis = redis.clone();
            tokio::spawn(async move {
                Self::publish_to_redis(redis, cmd.channel, cmd.serialized).await;
                drop(permit);
            });
        }
    }

    /// Background task that subscribes to Redis and forwards events locally.
    /// Emits a reconnect event after recovering from a Redis outage when there
    /// are active document subscriptions (design: websocket-scaling.md §Redis接続断).
    async fn subscription_loop(
        self: &Arc<Self>,
        mut subscribe_rx: mpsc::UnboundedReceiver<SubscribeCommand>,
    ) {
        let mut had_error = false;
        loop {
            match self.run_subscription(&mut subscribe_rx, had_error).await {
                Ok(()) => {
                    // Command channel closed (bus dropped), exit cleanly
                    tracing::info!("Redis document relay subscription loop exiting (bus dropped)");
                    break;
                }
                Err(e) => {
                    tracing::error!("Redis document relay subscription error: {}. Reconnecting...", e);
                    had_error = true;
                    // Drain pending commands so their oneshot acks are dropped (unblocking waiters)
                    while subscribe_rx.try_recv().is_ok() {}
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    async fn run_subscription(
        &self,
        subscribe_rx: &mut mpsc::UnboundedReceiver<SubscribeCommand>,
        is_reconnect: bool,
    ) -> Result<(), redis::RedisError> {
        let client = redis::Client::open(self.redis_url.as_str())?;
        let pubsub = client.get_async_pubsub().await?;

        // Split PubSub into sink (subscribe/unsubscribe) and stream (message receive).
        // This allows concurrent subscribe/unsubscribe while reading messages,
        // eliminating the need for timeout-based polling.
        let (mut sink, mut stream) = pubsub.split();

        // Re-subscribe to all active documents on (re)connect
        let docs: Vec<Uuid> = {
            let guard = self.doc_states.lock().unwrap();
            guard.keys().copied().collect()
        };
        for doc_id in &docs {
            sink.subscribe(format!("doc:{doc_id}")).await?;
            sink.subscribe(format!("ephemeral:{doc_id}")).await?;
        }
        if !docs.is_empty() {
            tracing::info!(
                count = docs.len(),
                "re-subscribed to document channels on reconnect"
            );
        }

        // After recovering from a Redis outage with active documents,
        // notify listeners to trigger PostgreSQL resync for connected clients.
        // During the outage, cross-node updates were not delivered.
        if is_reconnect && !docs.is_empty() {
            tracing::info!(
                count = docs.len(),
                "Redis reconnected with active documents, triggering resync"
            );
            let _ = self.reconnect_sender.send(());
        }

        tracing::info!("Redis document relay subscription loop started");

        loop {
            tokio::select! {
                // Receive messages from Redis
                msg = stream.next() => {
                    match msg {
                        Some(msg) => self.process_redis_message(msg),
                        None => {
                            // Stream ended (connection closed)
                            return Err(redis::RedisError::from((
                                redis::ErrorKind::IoError,
                                "PubSub stream ended",
                            )));
                        }
                    }
                }
                // Process subscribe/unsubscribe commands concurrently
                cmd = subscribe_rx.recv() => {
                    match cmd {
                        Some(SubscribeCommand::Subscribe(doc_id, ack)) => {
                            sink.subscribe(format!("doc:{doc_id}")).await?;
                            sink.subscribe(format!("ephemeral:{doc_id}")).await?;
                            let _ = ack.send(());
                        }
                        Some(SubscribeCommand::Unsubscribe(doc_id)) => {
                            sink.unsubscribe(format!("doc:{doc_id}")).await?;
                            sink.unsubscribe(format!("ephemeral:{doc_id}")).await?;
                        }
                        None => {
                            // Command channel closed (bus dropped)
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    /// Publish a serialized message to a Redis channel with a timeout.
    /// Shared by both document and ephemeral publish paths.
    async fn publish_to_redis(redis: RedisPool, channel: String, serialized: String) {
        if tokio::time::timeout(RELAY_PUBLISH_TIMEOUT, async {
            let mut conn = redis.connection();
            let result: Result<i32, _> = conn.publish(&channel, &serialized).await;
            if let Err(e) = result {
                tracing::warn!(
                    channel = %channel,
                    "Failed to publish relay to Redis: {}", e
                );
            }
        })
        .await
        .is_err()
        {
            tracing::warn!(
                channel = %channel,
                "relay publish timed out (local delivery unaffected)"
            );
        }
    }

    /// Process a single message received from Redis.
    fn process_redis_message(&self, msg: redis::Msg) {
        let channel: String = msg.get_channel_name().to_string();
        let raw_payload: String = match msg.get_payload() {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    channel = %channel,
                    "failed to get payload from Redis relay message"
                );
                return;
            }
        };

        match parse_relay_event(&channel, &raw_payload, &self.instance_id) {
            Ok(Some(event)) => {
                let _ = self.local_sender.send(event);
            }
            Ok(None) => {} // Self-origin, skip
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    channel = %channel,
                    "failed to parse relay message from Redis"
                );
            }
        }
    }

}

/// Parse a Redis relay message into a typed `DocumentRelayEvent`.
///
/// Extracted from `process_redis_message` for testability without a Redis connection.
/// Returns `Ok(None)` for self-origin messages (deduplication).
///
/// Deserializes the wire-format JSON into typed `DocumentRelayEventPayload`
/// (following the DeviceEvent/WorkspaceEvent pattern: typed on both ends
/// of the broadcast channel, DTO only for wire format).
fn parse_relay_event(
    channel: &str,
    raw_payload: &str,
    instance_id: &str,
) -> Result<Option<DocumentRelayEvent>, String> {
    let message: RedisRelayMessage =
        serde_json::from_str(raw_payload).map_err(|e| e.to_string())?;

    // Skip messages from self (already delivered locally)
    if message.origin_backend == instance_id {
        return Ok(None);
    }

    // Parse channel name to extract document_id and determine payload type.
    // Format: "doc:{uuid}" or "ephemeral:{uuid}"
    // Routing uses channel name, not payload type field
    // (design: websocket-scaling.md, channel design section).
    if let Some(id_str) = channel.strip_prefix("doc:") {
        let document_id = id_str.parse::<Uuid>().map_err(|e| e.to_string())?;
        // Deserialize by field structure via #[serde(untagged)], not by type field.
        // type is metadata for observability only (design: websocket-scaling.md L112).
        let payload: RelayPayload = serde_json::from_value(message.data)
            .map_err(|e| e.to_string())?;
        Ok(Some(DocumentRelayEvent {
            document_id,
            payload: DocumentRelayEventPayload::Document(payload),
        }))
    } else if let Some(id_str) = channel.strip_prefix("ephemeral:") {
        let document_id = id_str.parse::<Uuid>().map_err(|e| e.to_string())?;
        let payload = serde_json::from_value::<EphemeralRelayPayload>(message.data)
            .map_err(|e| e.to_string())?;
        Ok(Some(DocumentRelayEvent {
            document_id,
            payload: DocumentRelayEventPayload::Ephemeral(payload),
        }))
    } else {
        Err(format!("unexpected Redis channel name format: {channel}"))
    }
}

/// Timeout for each relay publish operation.
/// After this duration, the publish task is cancelled (accepted risk:
/// design: websocket-scaling.md §Relay publishのメッセージ喪失).
const RELAY_PUBLISH_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(5);

/// Maximum concurrent relay publish tasks (semaphore permits in the worker).
/// Under normal Redis (~1ms), permits return almost immediately.
/// Under degraded Redis, permits are held for up to RELAY_PUBLISH_TIMEOUT;
/// during that time the channel buffer absorbs new messages.
const MAX_CONCURRENT_PUBLISHES: usize = 64;

/// Bounded channel buffer size for the publish worker.
/// Provides buffering when all semaphore permits are in use (Redis degraded).
/// Messages are dropped only when both this buffer AND all permits are exhausted.
const PUBLISH_CHANNEL_BUFFER: usize = 256;

impl DocumentRelayPublisher for RedisDocumentRelayBus {
    fn publish_document_relay(&self, document_id: Uuid, payload: &RelayPayload) {
        let channel = format!("doc:{}", document_id);

        let (message_type, data) = match payload {
            RelayPayload::Update(p) => ("update", serde_json::to_value(p)),
            RelayPayload::Snapshot(p) => ("snapshot", serde_json::to_value(p)),
        };
        let data = match data {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to serialize RelayPayload: {}", e);
                return;
            }
        };

        let message = RedisRelayMessage {
            message_type: message_type.to_string(),
            data,
            origin_backend: self.instance_id.clone(),
        };

        let serialized = match serde_json::to_string(&message) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to serialize document relay message: {}", e);
                return;
            }
        };

        // Non-blocking enqueue to the publish worker. The channel buffer absorbs
        // transient spikes; the worker bounds concurrency via semaphore and gives
        // each message its own task with an independent timeout.
        // Drop only when both channel buffer AND all semaphore permits are exhausted
        // (accepted risk: recovered via client delta reconnect from PostgreSQL).
        match self.publish_tx.try_send(PublishCommand { channel: channel.clone(), serialized }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(
                    channel = %channel,
                    "relay publish buffer full, dropping message (local delivery unaffected)"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::error!(
                    channel = %channel,
                    "relay publish worker stopped, cross-node relay disabled"
                );
            }
        }
    }

    fn publish_ephemeral_relay(&self, document_id: Uuid, payload: &EphemeralRelayPayload) {
        let channel = format!("ephemeral:{}", document_id);

        let data = match serde_json::to_value(payload) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to serialize EphemeralRelayPayload: {}", e);
                return;
            }
        };

        let message = RedisRelayMessage {
            message_type: "ephemeral-message".to_string(),
            data,
            origin_backend: self.instance_id.clone(),
        };

        let serialized = match serde_json::to_string(&message) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to serialize ephemeral relay message: {}", e);
                return;
            }
        };

        // Non-blocking enqueue (same as document relay).
        // Ephemeral messages are best-effort; dropping under back-pressure is acceptable.
        match self.publish_tx.try_send(PublishCommand { channel: channel.clone(), serialized }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(
                    channel = %channel,
                    "ephemeral relay publish buffer full, dropping message (local delivery unaffected)"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::error!(
                    channel = %channel,
                    "relay publish worker stopped, cross-node relay disabled"
                );
            }
        }
    }
}

/// Timeout for awaiting Redis SUBSCRIBE/UNSUBSCRIBE confirmation.
/// If Redis is down, callers proceed in degraded mode after this timeout.
const SUBSCRIBE_ACK_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(5);

#[async_trait]
impl DocumentRelaySubscriber for RedisDocumentRelayBus {
    fn subscribe(&self) -> broadcast::Receiver<DocumentRelayEvent> {
        self.local_sender.subscribe()
    }

    fn subscribe_reconnect(&self) -> broadcast::Receiver<()> {
        self.reconnect_sender.subscribe()
    }

    async fn subscribe_document(&self, document_id: Uuid) {
        // State mutation and command enqueue are atomic under the lock to prevent
        // a race where a stale UNSUBSCRIBE cancels a new SUBSCRIBE (or vice versa).
        // UnboundedSender::send() is synchronous, so it's safe inside std::sync::Mutex.
        // Only the ack await is outside the lock.
        let (action, ack_rx) = {
            let mut states = self.doc_states.lock().unwrap();
            let action = decide_subscribe(&mut states, document_id);
            let ack_rx = if let SubscribeAction::Initiate(_) = &action {
                let (ack_tx, ack_rx) = oneshot::channel();
                let _ = self.subscribe_tx.send(SubscribeCommand::Subscribe(document_id, ack_tx));
                Some(ack_rx)
            } else {
                None
            };
            (action, ack_rx)
        };

        match action {
            SubscribeAction::Initiate(notify) => {
                match tokio::time::timeout(SUBSCRIBE_ACK_TIMEOUT, ack_rx.unwrap()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {
                        tracing::warn!(
                            document_id = %document_id,
                            "subscribe_document: ack channel closed (subscription loop may have restarted)"
                        );
                    }
                    Err(_) => {
                        tracing::warn!(
                            document_id = %document_id,
                            "subscribe_document: timed out waiting for Redis SUBSCRIBE, proceeding in degraded mode"
                        );
                    }
                }
                {
                    let mut states = self.doc_states.lock().unwrap();
                    finalize_subscribe(&mut states, document_id, &notify);
                }
                notify.notify_waiters();
            }
            SubscribeAction::WaitForInitiator(notify) => {
                // Register the Notified future with enable() before checking state
                // to prevent a lost-wakeup race: if notify_waiters() fires between
                // the lock release (above) and Notified creation, the wakeup is missed.
                // Sequence: enable() → re-check state → await (or skip).
                let notified = notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                // The initiator clears subscribe_notify BEFORE calling notify_waiters().
                // If subscribe_notify is already None, the initiator completed and we
                // may have missed the wakeup (before enable). Safe to skip waiting.
                let already_done = {
                    let states = self.doc_states.lock().unwrap();
                    is_subscribe_complete(&states, document_id)
                };

                if !already_done {
                    match tokio::time::timeout(SUBSCRIBE_ACK_TIMEOUT, notified).await {
                        Ok(()) => {}
                        Err(_) => {
                            tracing::warn!(
                                document_id = %document_id,
                                "subscribe_document: timed out waiting for in-progress subscribe, proceeding in degraded mode"
                            );
                        }
                    }
                }
            }
            SubscribeAction::AlreadySubscribed => {}
        }
    }

    fn unsubscribe_document(&self, document_id: Uuid) {
        // State mutation and command enqueue are atomic under the lock to prevent
        // a race where a stale UNSUBSCRIBE cancels a new SUBSCRIBE.
        // See subscribe_document comment for rationale.
        let mut states = self.doc_states.lock().unwrap();
        if decide_unsubscribe(&mut states, document_id) {
            let _ = self
                .subscribe_tx
                .send(SubscribeCommand::Unsubscribe(document_id));
        }
    }
}

// --- Subscription state machine (pure decision functions) ---
//
// Extracted from RedisDocumentRelayBus methods for testability without Redis.

/// Action to take when a new subscribe request arrives.
enum SubscribeAction {
    /// First connection for this document: initiate Redis SUBSCRIBE.
    Initiate(Arc<Notify>),
    /// Another connection is already subscribing: wait on Notify.
    WaitForInitiator(Arc<Notify>),
    /// Already subscribed: no action needed.
    AlreadySubscribed,
}

/// Decide what action to take for a subscribe request.
/// Increments refcount and creates Notify marker if this is the first connection.
fn decide_subscribe(
    states: &mut HashMap<Uuid, DocSubscriptionState>,
    document_id: Uuid,
) -> SubscribeAction {
    let state = states.entry(document_id).or_insert(DocSubscriptionState {
        refcount: 0,
        subscribe_notify: None,
    });
    state.refcount += 1;
    if state.refcount == 1 {
        let notify = Arc::new(Notify::new());
        state.subscribe_notify = Some(notify.clone());
        SubscribeAction::Initiate(notify)
    } else if let Some(ref notify) = state.subscribe_notify {
        SubscribeAction::WaitForInitiator(notify.clone())
    } else {
        SubscribeAction::AlreadySubscribed
    }
}

/// Clear the subscribe-in-progress marker after the initiator completes.
/// Only clears if the current marker matches the given generation (Arc::ptr_eq),
/// preventing a stale initiator from clearing a newer generation's marker.
fn finalize_subscribe(
    states: &mut HashMap<Uuid, DocSubscriptionState>,
    document_id: Uuid,
    generation: &Arc<Notify>,
) {
    if let Some(state) = states.get_mut(&document_id) {
        if let Some(ref current) = state.subscribe_notify {
            if Arc::ptr_eq(current, generation) {
                state.subscribe_notify = None;
            }
        }
    }
}

/// Check whether subscribe is complete (no in-progress marker).
fn is_subscribe_complete(
    states: &HashMap<Uuid, DocSubscriptionState>,
    document_id: Uuid,
) -> bool {
    states
        .get(&document_id)
        .map(|s| s.subscribe_notify.is_none())
        .unwrap_or(true)
}

/// Decide whether to send an unsubscribe command.
/// Decrements refcount and returns true if refcount reached zero (entry removed).
fn decide_unsubscribe(
    states: &mut HashMap<Uuid, DocSubscriptionState>,
    document_id: Uuid,
) -> bool {
    if let Some(state) = states.get_mut(&document_id) {
        state.refcount = state.refcount.saturating_sub(1);
        if state.refcount == 0 {
            states.remove(&document_id);
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use application::document_relay::{DocumentRelayEventPayload, RelayUpdatePayload};

    fn test_doc_id() -> Uuid {
        Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
    }

    fn build_redis_message(
        message_type: &str,
        data: serde_json::Value,
        origin_backend: &str,
    ) -> String {
        serde_json::to_string(&RedisRelayMessage {
            message_type: message_type.to_string(),
            data,
            origin_backend: origin_backend.to_string(),
        })
        .unwrap()
    }

    fn update_data() -> serde_json::Value {
        serde_json::json!({
            "ciphertext": "Y2lwaGVydGV4dA",
            "nonce": "bm9uY2U",
            "signature": "c2lnbmF0dXJl",
            "publicData": {"deviceId": "dev1"},
            "version": 42
        })
    }

    fn snapshot_data() -> serde_json::Value {
        serde_json::json!({
            "snapshotId": "snap-1",
            "ciphertext": "Y2lwaGVydGV4dA",
            "nonce": "bm9uY2U",
            "signature": "c2lnbmF0dXJl",
            "publicData": {"deviceId": "dev1"}
        })
    }

    fn ephemeral_data() -> serde_json::Value {
        serde_json::json!({
            "ciphertext": "Y2lwaGVydGV4dA",
            "nonce": "bm9uY2U",
            "signature": "c2lnbmF0dXJl",
            "publicData": {"deviceId": "dev1"}
        })
    }

    #[test]
    fn parse_doc_channel_update() {
        let doc_id = test_doc_id();
        let channel = format!("doc:{doc_id}");
        let payload = build_redis_message("update", update_data(), "other-backend");

        let event = parse_relay_event(&channel, &payload, "my-backend")
            .unwrap()
            .unwrap();

        assert_eq!(event.document_id, doc_id);
        assert!(matches!(
            event.payload,
            DocumentRelayEventPayload::Document(RelayPayload::Update(RelayUpdatePayload { version: 42, .. }))
        ));
    }

    #[test]
    fn parse_doc_channel_snapshot() {
        let doc_id = test_doc_id();
        let channel = format!("doc:{doc_id}");
        let payload = build_redis_message("snapshot", snapshot_data(), "other-backend");

        let event = parse_relay_event(&channel, &payload, "my-backend")
            .unwrap()
            .unwrap();

        assert_eq!(event.document_id, doc_id);
        assert!(matches!(
            event.payload,
            DocumentRelayEventPayload::Document(RelayPayload::Snapshot(_))
        ));
    }

    #[test]
    fn parse_ephemeral_channel() {
        let doc_id = test_doc_id();
        let channel = format!("ephemeral:{doc_id}");
        let payload =
            build_redis_message("ephemeral-message", ephemeral_data(), "other-backend");

        let event = parse_relay_event(&channel, &payload, "my-backend")
            .unwrap()
            .unwrap();

        assert_eq!(event.document_id, doc_id);
        assert!(matches!(
            event.payload,
            DocumentRelayEventPayload::Ephemeral(_)
        ));
    }

    #[test]
    fn skip_self_origin() {
        let doc_id = test_doc_id();
        let channel = format!("doc:{doc_id}");
        let payload = build_redis_message("update", update_data(), "my-backend");

        let result = parse_relay_event(&channel, &payload, "my-backend").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn reject_invalid_channel_format() {
        let payload = build_redis_message("update", update_data(), "other-backend");

        let result = parse_relay_event("unknown:123", &payload, "my-backend");
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_uuid_in_channel() {
        let payload = build_redis_message("update", update_data(), "other-backend");

        let result = parse_relay_event("doc:not-a-uuid", &payload, "my-backend");
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_json_payload() {
        let doc_id = test_doc_id();
        let channel = format!("doc:{doc_id}");

        let result = parse_relay_event(&channel, "not json", "my-backend");
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_relay_payload_data() {
        let doc_id = test_doc_id();
        let channel = format!("doc:{doc_id}");
        // Valid RedisRelayMessage envelope but invalid RelayPayload data
        let payload =
            build_redis_message("update", serde_json::json!({"invalid": true}), "other-backend");

        let result = parse_relay_event(&channel, &payload, "my-backend");
        assert!(result.is_err());
    }

    #[test]
    fn redis_relay_message_serialization_roundtrip() {
        let message = RedisRelayMessage {
            message_type: "update".to_string(),
            data: update_data(),
            origin_backend: "backend-1".to_string(),
        };

        let serialized = serde_json::to_string(&message).unwrap();
        let deserialized: RedisRelayMessage = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.message_type, "update");
        assert_eq!(deserialized.origin_backend, "backend-1");
    }

    // --- Subscription state machine tests ---

    #[test]
    fn subscribe_first_connection_returns_initiate() {
        let mut states = HashMap::new();
        let doc_id = test_doc_id();

        let action = decide_subscribe(&mut states, doc_id);
        assert!(matches!(action, SubscribeAction::Initiate(_)));
        assert_eq!(states[&doc_id].refcount, 1);
        assert!(states[&doc_id].subscribe_notify.is_some());
    }

    #[test]
    fn subscribe_concurrent_returns_waiter() {
        let mut states = HashMap::new();
        let doc_id = test_doc_id();

        // First connection: Initiate
        let action1 = decide_subscribe(&mut states, doc_id);
        assert!(matches!(action1, SubscribeAction::Initiate(_)));

        // Second connection while first is in-progress: WaitForInitiator
        let action2 = decide_subscribe(&mut states, doc_id);
        assert!(matches!(action2, SubscribeAction::WaitForInitiator(_)));
        assert_eq!(states[&doc_id].refcount, 2);
    }

    #[test]
    fn subscribe_after_complete_returns_already_subscribed() {
        let mut states = HashMap::new();
        let doc_id = test_doc_id();

        // First connection: Initiate
        let notify = match decide_subscribe(&mut states, doc_id) {
            SubscribeAction::Initiate(n) => n,
            _ => panic!("expected Initiate"),
        };

        // Finalize (simulate ack received)
        finalize_subscribe(&mut states, doc_id, &notify);
        assert!(states[&doc_id].subscribe_notify.is_none());

        // Second connection after complete: AlreadySubscribed
        let action = decide_subscribe(&mut states, doc_id);
        assert!(matches!(action, SubscribeAction::AlreadySubscribed));
        assert_eq!(states[&doc_id].refcount, 2);
    }

    #[test]
    fn finalize_subscribe_ignores_stale_generation() {
        let mut states = HashMap::new();
        let doc_id = test_doc_id();

        // First generation
        let old_notify = match decide_subscribe(&mut states, doc_id) {
            SubscribeAction::Initiate(n) => n,
            _ => panic!("expected Initiate"),
        };

        // Simulate: unsubscribe removes entry, then new subscribe creates new generation
        states.remove(&doc_id);
        let new_notify = match decide_subscribe(&mut states, doc_id) {
            SubscribeAction::Initiate(n) => n,
            _ => panic!("expected Initiate"),
        };

        // Stale initiator tries to finalize with old generation — must NOT clear new marker
        finalize_subscribe(&mut states, doc_id, &old_notify);
        assert!(states[&doc_id].subscribe_notify.is_some());

        // New initiator finalizes with correct generation — clears marker
        finalize_subscribe(&mut states, doc_id, &new_notify);
        assert!(states[&doc_id].subscribe_notify.is_none());
    }

    #[test]
    fn is_subscribe_complete_returns_true_after_finalize() {
        let mut states = HashMap::new();
        let doc_id = test_doc_id();

        let notify = match decide_subscribe(&mut states, doc_id) {
            SubscribeAction::Initiate(n) => n,
            _ => panic!("expected Initiate"),
        };
        assert!(!is_subscribe_complete(&states, doc_id));

        finalize_subscribe(&mut states, doc_id, &notify);
        assert!(is_subscribe_complete(&states, doc_id));
    }

    #[test]
    fn is_subscribe_complete_returns_true_for_unknown_doc() {
        let states = HashMap::new();
        let doc_id = test_doc_id();
        assert!(is_subscribe_complete(&states, doc_id));
    }

    #[test]
    fn unsubscribe_with_remaining_connections_does_not_remove() {
        let mut states = HashMap::new();
        let doc_id = test_doc_id();

        // Subscribe twice
        decide_subscribe(&mut states, doc_id);
        decide_subscribe(&mut states, doc_id);
        assert_eq!(states[&doc_id].refcount, 2);

        // Unsubscribe once: refcount decrements but entry stays
        assert!(!decide_unsubscribe(&mut states, doc_id));
        assert_eq!(states[&doc_id].refcount, 1);
    }

    #[test]
    fn unsubscribe_last_connection_removes_entry() {
        let mut states = HashMap::new();
        let doc_id = test_doc_id();

        decide_subscribe(&mut states, doc_id);
        assert_eq!(states[&doc_id].refcount, 1);

        // Last connection: returns true (send UNSUBSCRIBE), entry removed
        assert!(decide_unsubscribe(&mut states, doc_id));
        assert!(!states.contains_key(&doc_id));
    }

    #[test]
    fn unsubscribe_unknown_document_is_noop() {
        let mut states = HashMap::new();
        let doc_id = test_doc_id();

        assert!(!decide_unsubscribe(&mut states, doc_id));
    }
}
