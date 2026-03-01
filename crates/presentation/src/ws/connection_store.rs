//! In-memory WebSocket connection store
//!
//! Manages per-document rooms with broadcast channels for relaying
//! messages between connected clients. Empty rooms are automatically
//! cleaned up when the last client disconnects.
//!
//! Supports targeted messaging:
//! - `send_to()` → specific client only
//! - `broadcast_except()` → all clients except one

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;
use uuid::Uuid;

use super::messages::WsOutMessage;

/// Unique identifier for a WebSocket connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(Uuid);

impl ConnectionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

/// Information about a single connection
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub user_id: Uuid,
    /// Per-connection channel for targeted messages (bounded to prevent slow-client OOM)
    pub sender: mpsc::Sender<WsOutMessage>,
}

/// Per-connection token bucket for ephemeral message rate limiting.
/// Prevents DB amplification DoS via high-frequency ephemeral messages.
pub struct EphemeralRateLimiter {
    /// Available tokens (scaled by 1000 to avoid floating point)
    tokens_x1000: AtomicU64,
    /// Last refill timestamp in milliseconds
    last_refill_ms: AtomicU64,
}

/// Ephemeral rate limit: 10 messages per second
const EPHEMERAL_RATE_LIMIT: u64 = 10;
/// Ephemeral burst capacity: 20 messages
const EPHEMERAL_BURST: u64 = 20;

impl EphemeralRateLimiter {
    fn new() -> Self {
        Self {
            tokens_x1000: AtomicU64::new(EPHEMERAL_BURST * 1000),
            last_refill_ms: AtomicU64::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0),
            ),
        }
    }

    /// Try to consume one token. Returns true if allowed, false if rate limited.
    pub fn try_acquire(&self) -> bool {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Refill tokens based on elapsed time
        let last = self.last_refill_ms.load(Ordering::Relaxed);
        let elapsed_ms = now_ms.saturating_sub(last);
        if elapsed_ms > 0 {
            let refill = elapsed_ms * EPHEMERAL_RATE_LIMIT; // tokens_x1000 per ms = rate * 1000 / 1000
            let current = self.tokens_x1000.load(Ordering::Relaxed);
            let new_tokens = (current + refill).min(EPHEMERAL_BURST * 1000);
            // Best-effort CAS: if another thread raced, we skip the refill (acceptable)
            let _ = self.tokens_x1000.compare_exchange(
                current,
                new_tokens,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            let _ = self.last_refill_ms.compare_exchange(
                last,
                now_ms,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }

        // Try to consume one token (1000 units)
        loop {
            let current = self.tokens_x1000.load(Ordering::Relaxed);
            if current < 1000 {
                return false;
            }
            match self.tokens_x1000.compare_exchange_weak(
                current,
                current - 1000,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }
}

/// A room for a single document, holding per-connection channels for targeted messaging
pub struct DocumentRoom {
    connections: DashMap<ConnectionId, ConnectionInfo>,
    /// Per-connection ephemeral rate limiters (token bucket: 10/sec, burst 20)
    ephemeral_rate_limiters: DashMap<ConnectionId, EphemeralRateLimiter>,
}

impl DocumentRoom {
    fn new() -> Self {
        Self {
            connections: DashMap::new(),
            ephemeral_rate_limiters: DashMap::new(),
        }
    }

    /// Check if an ephemeral message is allowed for this connection (rate limit).
    /// Returns true if allowed, false if rate limited (message should be dropped).
    pub fn check_ephemeral_rate_limit(&self, conn_id: ConnectionId) -> bool {
        self.ephemeral_rate_limiters
            .entry(conn_id)
            .or_insert_with(EphemeralRateLimiter::new)
            .try_acquire()
    }

    /// Remove a connection and its associated rate limiter.
    fn remove_connection(&self, conn_id: ConnectionId) {
        self.connections.remove(&conn_id);
        self.ephemeral_rate_limiters.remove(&conn_id);
    }

    /// Send a message to a specific client only (via per-connection channel).
    ///
    /// If the channel is full, the connection is removed to force a reconnect
    /// rather than silently dropping confirmations (which would leak the pending
    /// queue and prevent snapshot threshold from being reached).
    pub fn send_to(&self, conn_id: ConnectionId, msg: WsOutMessage) {
        if let Some(info) = self.connections.get(&conn_id) {
            if info.sender.try_send(msg).is_err() {
                tracing::warn!("Per-connection channel full or closed for {conn_id:?}, forcing disconnect for resync");
                drop(info); // Release read lock before write lock
                self.remove_connection(conn_id);
            }
        }
    }

    /// Broadcast to all clients EXCEPT the specified one.
    ///
    /// If a per-connection channel is full, the connection is removed — dropping
    /// the mpsc::Sender closes the receiver, breaking the outbound loop, which
    /// triggers WebSocket close and client auto-reconnect in delta mode.
    /// This prevents silent message loss that would cause permanent sync divergence.
    pub fn broadcast_except(&self, exclude: ConnectionId, msg: WsOutMessage) {
        let mut stale = Vec::new();
        for entry in self.connections.iter() {
            if *entry.key() != exclude {
                if entry.value().sender.try_send(msg.clone()).is_err() {
                    tracing::warn!("Per-connection channel full or closed for {:?}, forcing disconnect for resync", entry.key());
                    stale.push(*entry.key());
                }
            }
        }
        for conn_id in stale {
            self.remove_connection(conn_id);
        }
    }

    pub fn has_connection(&self, conn_id: ConnectionId) -> bool {
        self.connections.contains_key(&conn_id)
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Get distinct user IDs of all connected clients.
    /// Used for lazy RBAC checks after broadcast.
    pub fn connected_user_ids(&self) -> Vec<Uuid> {
        let mut user_ids = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for entry in self.connections.iter() {
            if seen.insert(entry.value().user_id) {
                user_ids.push(entry.value().user_id);
            }
        }
        user_ids
    }

    /// Evict all connections for a specific user, sending a message before removal.
    pub fn evict_user(&self, user_id: Uuid, reason: WsOutMessage) {
        let to_remove: Vec<ConnectionId> = self
            .connections
            .iter()
            .filter(|e| e.value().user_id == user_id)
            .map(|e| *e.key())
            .collect();
        for conn_id in to_remove {
            if let Some(info) = self.connections.get(&conn_id) {
                let _ = info.sender.try_send(reason.clone());
            }
            self.remove_connection(conn_id);
        }
    }
}

/// Store managing all document rooms
#[derive(Clone)]
pub struct DocumentConnectionStore {
    rooms: Arc<DashMap<Uuid, Arc<DocumentRoom>>>,
}

impl Default for DocumentConnectionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DocumentConnectionStore {
    pub fn new() -> Self {
        Self {
            rooms: Arc::new(DashMap::new()),
        }
    }

    /// Per-connection channel capacity (bounded to prevent slow-client OOM)
    const PER_CONNECTION_CHANNEL_CAPACITY: usize = 256;

    /// Maximum WS connections per user per document (prevents multi-connection RBAC amplification)
    const MAX_CONNECTIONS_PER_USER_PER_DOCUMENT: usize = 3;

    /// Join a document room.
    /// Returns (ConnectionId, per-connection receiver, room Arc).
    /// Creates the room if it doesn't exist.
    ///
    /// If the user already has `MAX_CONNECTIONS_PER_USER_PER_DOCUMENT` connections,
    /// excess connections are evicted to make room (eviction order is non-deterministic).
    ///
    /// Best-effort: concurrent join() calls may temporarily exceed the cap due to
    /// TOCTOU between count and insert. The cap converges on the next join() call.
    pub fn join(
        &self,
        document_id: Uuid,
        user_id: Uuid,
    ) -> (ConnectionId, mpsc::Receiver<WsOutMessage>, Arc<DocumentRoom>) {
        let room = self
            .rooms
            .entry(document_id)
            .or_insert_with(|| Arc::new(DocumentRoom::new()))
            .clone();

        // Enforce per-user connection cap: evict connections if at limit (non-deterministic order)
        let user_conns: Vec<ConnectionId> = room
            .connections
            .iter()
            .filter(|e| e.value().user_id == user_id)
            .map(|e| *e.key())
            .collect();
        if user_conns.len() >= Self::MAX_CONNECTIONS_PER_USER_PER_DOCUMENT {
            // Evict enough connections to make room for the new one
            let to_evict = user_conns.len() - Self::MAX_CONNECTIONS_PER_USER_PER_DOCUMENT + 1;
            for conn_id in user_conns.into_iter().take(to_evict) {
                tracing::info!(
                    "Per-user connection cap: evicting connection {conn_id:?} for user {user_id} on document {document_id}"
                );
                room.send_to(conn_id, WsOutMessage::Unauthorized);
                room.remove_connection(conn_id);
            }
        }

        let conn_id = ConnectionId::new();
        let (tx, rx) = mpsc::channel(Self::PER_CONNECTION_CHANNEL_CAPACITY);
        room.connections.insert(
            conn_id,
            ConnectionInfo {
                user_id,
                sender: tx,
            },
        );

        (conn_id, rx, room)
    }

    /// Leave a document room. Removes the connection and cleans up empty rooms.
    pub fn leave(&self, document_id: Uuid, conn_id: ConnectionId) {
        if let Some(room) = self.rooms.get(&document_id) {
            room.remove_connection(conn_id);
            if room.connections.is_empty() {
                drop(room);
                self.rooms
                    .remove_if(&document_id, |_, room| room.connections.is_empty());
            }
        }
    }

    /// Disconnect a user from specific document rooms only.
    /// Used for workspace-scoped disconnects (member removed/role changed).
    /// Cleans up empty rooms after disconnection.
    pub fn disconnect_user_from_documents(&self, user_id: Uuid, document_ids: &[Uuid]) {
        for doc_id in document_ids {
            if let Some(room) = self.rooms.get(doc_id) {
                let to_remove: Vec<ConnectionId> = room
                    .connections
                    .iter()
                    .filter(|e| e.value().user_id == user_id)
                    .map(|e| *e.key())
                    .collect();
                for conn_id in to_remove {
                    if let Some(info) = room.connections.get(&conn_id) {
                        let _ = info.sender.try_send(WsOutMessage::Unauthorized);
                    }
                    room.remove_connection(conn_id);
                }
                if room.connections.is_empty() {
                    drop(room);
                    self.rooms
                        .remove_if(doc_id, |_, room| room.connections.is_empty());
                }
            }
        }
    }

    /// Get the connection count for a document
    pub fn connection_count(&self, document_id: Uuid) -> usize {
        self.rooms
            .get(&document_id)
            .map(|room| room.connection_count())
            .unwrap_or(0)
    }
}

impl application::workspace::DocumentConnectionManager for DocumentConnectionStore {
    fn disconnect_user_from_documents(&self, user_id: application::types::UserId, document_ids: &[application::types::DocumentId]) {
        let uid = user_id.as_uuid();
        let doc_uuids: Vec<Uuid> = document_ids.iter().map(|d| d.as_uuid()).collect();
        self.disconnect_user_from_documents(uid, &doc_uuids);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_creates_room_and_leave_cleans_up() {
        let store = DocumentConnectionStore::new();
        let doc_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let (conn1, _rx1, _room1) = store.join(doc_id, user_id);
        assert_eq!(store.connection_count(doc_id), 1);

        let (conn2, _rx2, _room2) = store.join(doc_id, user_id);
        assert_eq!(store.connection_count(doc_id), 2);

        store.leave(doc_id, conn1);
        assert_eq!(store.connection_count(doc_id), 1);

        store.leave(doc_id, conn2);
        assert_eq!(store.connection_count(doc_id), 0);

        assert_eq!(store.rooms.len(), 0);
    }

    #[tokio::test]
    async fn send_to_reaches_only_target() {
        let store = DocumentConnectionStore::new();
        let doc_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let (conn1, mut rx1, room) = store.join(doc_id, user_id);
        let (_conn2, mut rx2, _) = store.join(doc_id, user_id);

        room.send_to(conn1, WsOutMessage::DocumentNotFound);

        let msg = rx1.recv().await.unwrap();
        assert!(matches!(msg, WsOutMessage::DocumentNotFound));

        assert!(rx2.try_recv().is_err());
    }

    #[tokio::test]
    async fn disconnect_user_from_documents_scoped() {
        let store = DocumentConnectionStore::new();
        let user_id = Uuid::new_v4();
        let doc1 = Uuid::new_v4();
        let doc2 = Uuid::new_v4();
        let doc3 = Uuid::new_v4();

        let (_c1, mut rx1, _) = store.join(doc1, user_id);
        let (_c2, mut rx2, _) = store.join(doc2, user_id);
        let (_c3, _rx3, _) = store.join(doc3, user_id);

        // Only disconnect from doc1 and doc2
        store.disconnect_user_from_documents(user_id, &[doc1, doc2]);

        // doc1 and doc2 should receive Unauthorized
        let msg1 = rx1.recv().await.unwrap();
        assert!(matches!(msg1, WsOutMessage::Unauthorized));
        let msg2 = rx2.recv().await.unwrap();
        assert!(matches!(msg2, WsOutMessage::Unauthorized));

        // doc3 should still have a connection
        assert_eq!(store.connection_count(doc3), 1);
        // doc1 and doc2 should be empty
        assert_eq!(store.connection_count(doc1), 0);
        assert_eq!(store.connection_count(doc2), 0);
    }

    #[tokio::test]
    async fn broadcast_except_skips_excluded() {
        let store = DocumentConnectionStore::new();
        let doc_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let (conn1, mut rx1, room) = store.join(doc_id, user_id);
        let (_conn2, mut rx2, _) = store.join(doc_id, user_id);

        room.broadcast_except(conn1, WsOutMessage::DocumentNotFound);

        assert!(rx1.try_recv().is_err());

        let msg = rx2.recv().await.unwrap();
        assert!(matches!(msg, WsOutMessage::DocumentNotFound));
    }
}
