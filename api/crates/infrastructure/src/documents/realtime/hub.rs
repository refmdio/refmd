use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{Mutex, RwLock};
use tokio::time::Duration;
use uuid::Uuid;

use crate::core::crypto::Ed25519Verifier;
use crate::documents::realtime::{DynRealtimeSink, DynRealtimeStream};
use application::documents::ports::realtime::realtime_persistence_port::{
    ContentEncryptionMeta, DocPersistencePort, EncryptedUpdateData,
};
use application::documents::ports::realtime::realtime_types::{
    MessageType, RealtimeMessage,
};
use application::documents::services::realtime::snapshot::SnapshotService;

type SharedRealtimeSink = Arc<Mutex<DynRealtimeSink>>;

/// E2EE Document Room - simple relay without CRDT merge
/// Server only relays encrypted messages and verifies signatures
#[derive(Clone)]
pub struct E2EEDocumentRoom {
    /// Connected clients for broadcasting
    clients: Arc<RwLock<Vec<SharedRealtimeSink>>>,
    /// Latest persisted sequence number
    pub seq: Arc<Mutex<i64>>,
    /// Flag to skip filesystem persistence (e.g., after ingest)
    pub skip_fs_persist: Arc<AtomicBool>,
}

impl E2EEDocumentRoom {
    pub fn new(start_seq: i64) -> Self {
        Self {
            clients: Arc::new(RwLock::new(Vec::new())),
            seq: Arc::new(Mutex::new(start_seq)),
            skip_fs_persist: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Add a client to the room
    pub async fn add_client(&self, sink: SharedRealtimeSink) {
        self.clients.write().await.push(sink);
    }

    /// Remove a client from the room
    pub async fn remove_client(&self, sink: &SharedRealtimeSink) {
        let mut clients = self.clients.write().await;
        clients.retain(|c| !Arc::ptr_eq(c, sink));
    }

    /// Broadcast message to all clients except the sender
    pub async fn broadcast_except(&self, message: &[u8], sender: &SharedRealtimeSink) {
        let clients = self.clients.read().await;
        for client in clients.iter() {
            if Arc::ptr_eq(client, sender) {
                continue;
            }
            let mut guard = client.lock().await;
            if let Err(e) = guard.send(message.to_vec()).await {
                tracing::debug!(error = %e, "e2ee_broadcast_send_failed");
            }
        }
    }

    /// Get current client count
    pub async fn client_count(&self) -> usize {
        self.clients.read().await.len()
    }
}

/// E2EE Hub - manages document rooms with encrypted relay
#[derive(Clone)]
pub struct Hub {
    /// Document rooms by document ID
    inner: Arc<RwLock<HashMap<String, Arc<E2EEDocumentRoom>>>>,
    /// Snapshot service for persistence
    snapshot_service: Arc<SnapshotService>,
    /// Document persistence port
    persistence: Arc<dyn DocPersistencePort>,
    /// Edit flags per document
    edit_flags: Arc<RwLock<HashMap<String, Arc<AtomicBool>>>>,
    /// Auto archive interval (0 = disabled)
    #[allow(dead_code)]
    auto_archive_interval: Duration,
}

impl Hub {
    /// Create a new Hub
    ///
    /// Note: hydration_service parameter is kept for API compatibility but not used
    /// (clients handle hydration with their own keys)
    pub fn new(
        _hydration_service: Arc<dyn std::any::Any + Send + Sync>,
        snapshot_service: Arc<SnapshotService>,
        persistence: Arc<dyn DocPersistencePort>,
        auto_archive_interval: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            snapshot_service,
            persistence,
            edit_flags: Arc::new(RwLock::new(HashMap::new())),
            auto_archive_interval,
        }
    }

    /// Get or create a document room
    ///
    /// The room is a simple relay structure without Yjs Doc.
    /// The server doesn't process document content, only relays encrypted messages.
    pub async fn get_or_create(&self, doc_id: &str) -> anyhow::Result<Arc<E2EEDocumentRoom>> {
        // Return existing room if available
        if let Some(r) = self.inner.read().await.get(doc_id).cloned() {
            return Ok(r);
        }

        let doc_uuid = Uuid::parse_str(doc_id)?;

        // Get the latest sequence number from persistence
        let start_seq = self
            .persistence
            .latest_update_seq(&doc_uuid)
            .await?
            .unwrap_or(0);

        // Create a simple E2EE room (no Yjs Doc needed)
        let room = Arc::new(E2EEDocumentRoom::new(start_seq));

        // Register the room
        self.inner
            .write()
            .await
            .insert(doc_id.to_string(), room.clone());
        let _ = self.ensure_edit_flag(doc_id).await;

        tracing::debug!(
            document_id = %doc_id,
            start_seq = start_seq,
            "e2ee_room_created"
        );

        Ok(room)
    }

    pub fn snapshot_service(&self) -> Arc<SnapshotService> {
        self.snapshot_service.clone()
    }

    /// Get encrypted snapshot with metadata (nonce, signature, seq_at_snapshot)
    ///
    /// Returns the encrypted snapshot directly from persistence.
    /// The server cannot decode the content.
    pub async fn get_snapshot(
        &self,
        doc_id: &str,
    ) -> anyhow::Result<Option<application::documents::ports::realtime::realtime_port::SnapshotData>>
    {
        use application::documents::ports::realtime::realtime_port::SnapshotData;

        let uuid = match Uuid::parse_str(doc_id) {
            Ok(id) => id,
            Err(_) => return Ok(None),
        };

        // Get encrypted snapshot from persistence
        if let Ok(Some(entry)) = self.persistence.latest_snapshot_entry(&uuid).await {
            return Ok(Some(SnapshotData {
                data: entry.bytes,
                nonce: entry.nonce,
                signature: entry.signature,
                seq_at_snapshot: entry.seq_at_snapshot,
            }));
        }

        Ok(None)
    }

    /// Get encrypted updates since a given sequence number
    ///
    /// Used by REST API to retrieve pending updates for content reconstruction.
    pub async fn get_updates_since(
        &self,
        doc_id: &str,
        since_seq: i64,
    ) -> anyhow::Result<Vec<application::documents::ports::realtime::realtime_port::EncryptedUpdateEntry>>
    {
        use application::documents::ports::realtime::realtime_port::EncryptedUpdateEntry;

        let uuid = match Uuid::parse_str(doc_id) {
            Ok(id) => id,
            Err(_) => return Ok(Vec::new()),
        };

        let updates = self.persistence.get_updates_since(&uuid, since_seq).await?;

        Ok(updates
            .into_iter()
            .map(|u| EncryptedUpdateEntry {
                seq: u.seq,
                data: u.data,
                nonce: u.nonce,
                signature: u.signature,
                public_key: u.public_key,
            })
            .collect())
    }

    /// Get plaintext content is not available
    ///
    /// Returns None as the server cannot decrypt content.
    pub async fn get_content(&self, _doc_id: &str) -> anyhow::Result<Option<String>> {
        // Server cannot access plaintext content
        Ok(None)
    }

    /// Apply plaintext snapshot is not available
    ///
    /// Use apply_encrypted_snapshot instead.
    pub async fn apply_snapshot(
        &self,
        _doc_id: &str,
        _snapshot: &yrs::Doc,
    ) -> anyhow::Result<()> {
        anyhow::bail!("apply_snapshot not available, use apply_encrypted_snapshot")
    }

    /// Apply encrypted snapshot
    pub async fn apply_encrypted_snapshot(
        &self,
        doc_id: &str,
        data: &[u8],
        nonce: Option<&[u8]>,
        signature: Option<&[u8]>,
    ) -> anyhow::Result<()> {
        let doc_uuid = Uuid::parse_str(doc_id)?;

        // Get the next version number
        let version = self
            .persistence
            .latest_snapshot_version(&doc_uuid)
            .await?
            .unwrap_or(0)
            + 1;

        // Get current seq to record in snapshot (for E2EE sync)
        let room = self.get_or_create(doc_id).await?;
        let current_seq = {
            let guard = room.seq.lock().await;
            *guard
        };

        // Store the encrypted snapshot with metadata including seq_at_snapshot
        let encryption_meta = Some(ContentEncryptionMeta {
            nonce: nonce.map(|n| n.to_vec()),
            signature: signature.map(|s| s.to_vec()),
            seq_at_snapshot: Some(current_seq),
        });

        self.persistence
            .persist_snapshot(&doc_uuid, version, data, encryption_meta.as_ref())
            .await
            .map_err(|e| anyhow::anyhow!("failed to persist encrypted snapshot: {:?}", e))?;

        tracing::debug!(
            document_id = %doc_id,
            version = version,
            seq_at_snapshot = current_seq,
            "e2ee_snapshot_persisted"
        );

        Ok(())
    }

    /// Apply encrypted update
    pub async fn apply_encrypted_update(
        &self,
        doc_id: &str,
        data: &[u8],
        nonce: Option<&[u8]>,
        signature: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> anyhow::Result<()> {
        let doc_uuid = Uuid::parse_str(doc_id)?;

        // Get the current seq number (create room if needed to track seq)
        let room = self.get_or_create(doc_id).await?;
        let seq = {
            let mut guard = room.seq.lock().await;
            *guard += 1;
            *guard
        };

        // Store the encrypted update with metadata
        let update_data = EncryptedUpdateData {
            data: data.to_vec(),
            nonce: nonce.map(|n| n.to_vec()),
            signature: signature.map(|s| s.to_vec()),
            public_key: public_key.map(|p| p.to_vec()),
        };

        self.persistence
            .append_encrypted_update_with_seq(&doc_uuid, seq, &update_data)
            .await
            .map_err(|e| anyhow::anyhow!("failed to persist encrypted update: {:?}", e))?;

        tracing::debug!(
            document_id = %doc_id,
            seq = seq,
            "e2ee_update_persisted"
        );

        Ok(())
    }
}

impl Hub {
    /// Prune old updates for all documents
    ///
    /// Snapshot creation is client-driven. This method only
    /// prunes old encrypted updates after the window.
    pub async fn snapshot_all(
        &self,
        _keep_versions: i64,
        updates_keep_window: i64,
    ) -> anyhow::Result<()> {
        let rooms: Vec<(String, Arc<E2EEDocumentRoom>)> = {
            let map = self.inner.read().await;
            map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        for (doc_id, room) in rooms {
            let doc_uuid = match Uuid::parse_str(&doc_id) {
                Ok(x) => x,
                Err(_) => continue,
            };
            let current_seq = {
                let guard = room.seq.lock().await;
                *guard
            };
            let cutoff = (current_seq - updates_keep_window).max(0);

            // Prune old updates (encrypted updates before cutoff)
            if let Err(e) = self.persistence.prune_updates_before(&doc_uuid, cutoff).await {
                tracing::warn!(
                    document_id = %doc_id,
                    error = %e,
                    "e2ee_prune_updates_failed"
                );
            }
        }
        Ok(())
    }

    /// Force save to filesystem is not available
    ///
    /// The server cannot decrypt content to write markdown.
    pub async fn force_save_to_fs(&self, doc_id: &str) -> anyhow::Result<()> {
        tracing::warn!(
            document_id = %doc_id,
            "force_save_to_fs called - server cannot decrypt content"
        );
        // We cannot write plaintext markdown
        // This is a no-op but we don't fail to maintain API compatibility
        Ok(())
    }

    /// Subscribe to a document room for realtime collaboration
    ///
    /// This method:
    /// 1. Sends initial encrypted snapshot to the client
    /// 2. Processes incoming E2EE messages (JSON format)
    /// 3. Verifies Ed25519 signatures
    /// 4. Relays valid messages to other clients
    /// 5. Persists encrypted updates to the database
    pub async fn subscribe(
        &self,
        doc_id: &str,
        sink: DynRealtimeSink,
        stream: DynRealtimeStream,
        can_edit: bool,
    ) -> anyhow::Result<()> {
        let room = self.get_or_create(doc_id).await?;
        let sink: SharedRealtimeSink = Arc::new(Mutex::new(sink));
        let edit_flag = self.ensure_edit_flag(doc_id).await;
        let effective_can_edit = can_edit && edit_flag.load(Ordering::Relaxed);

        // Add client to room for broadcast
        room.add_client(sink.clone()).await;

        // Send initial encrypted snapshot if available
        let snapshot_seq = if let Ok(Some(snapshot)) = self.get_snapshot(doc_id).await {
            let init_msg = serde_json::json!({
                "type": "init",
                "snapshot": {
                    "data": base64::engine::general_purpose::STANDARD.encode(&snapshot.data),
                    "nonce": snapshot.nonce.map(|n| base64::engine::general_purpose::STANDARD.encode(&n)),
                    "signature": snapshot.signature.map(|s| base64::engine::general_purpose::STANDARD.encode(&s)),
                    "seq_at_snapshot": snapshot.seq_at_snapshot,
                }
            });
            let msg_bytes = serde_json::to_vec(&init_msg)?;
            let mut guard = sink.lock().await;
            if let Err(e) = guard.send(msg_bytes).await {
                tracing::debug!(error = %e, "e2ee_init_send_failed");
            }
            drop(guard);
            // Use seq_at_snapshot to determine which updates to send
            snapshot.seq_at_snapshot.unwrap_or(0)
        } else {
            0
        };

        // Send pending encrypted updates since last snapshot (only updates after snapshot)
        let doc_uuid = Uuid::parse_str(doc_id)?;
        if let Ok(updates) = self.persistence.get_updates_since(&doc_uuid, snapshot_seq).await {
            for update in updates {
                let update_msg = serde_json::json!({
                    "type": "sync_update",
                    "update": {
                        "data": base64::engine::general_purpose::STANDARD.encode(&update.data),
                        "nonce": update.nonce.map(|n| base64::engine::general_purpose::STANDARD.encode(&n)),
                        "signature": update.signature.map(|s| base64::engine::general_purpose::STANDARD.encode(&s)),
                        "public_key": update.public_key.map(|p| base64::engine::general_purpose::STANDARD.encode(&p)),
                        "seq": update.seq,
                    }
                });
                let msg_bytes = serde_json::to_vec(&update_msg)?;
                let mut guard = sink.lock().await;
                if let Err(e) = guard.send(msg_bytes).await {
                    tracing::debug!(error = %e, "e2ee_sync_update_send_failed");
                    break;
                }
                drop(guard);
            }
        }

        // Process incoming messages
        let mut stream = stream;
        while let Some(result) = stream.next().await {
            let data = match result {
                Ok(d) => d,
                Err(e) => {
                    tracing::debug!(error = %e, "e2ee_stream_error");
                    break;
                }
            };

            // Parse E2EE message (secsync-compatible format)
            let msg: RealtimeMessage = match serde_json::from_slice(&data) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!(error = %e, "e2ee_parse_error");
                    continue;
                }
            };

            // Extract public key from publicData based on message type
            let (pub_key_b64, msg_doc_id) = match msg.msg_type {
                MessageType::Update => {
                    match msg.parse_update_public_data() {
                        Ok(pd) => (pd.pub_key, pd.doc_id),
                        Err(e) => {
                            tracing::debug!(error = %e, "e2ee_parse_update_public_data_error");
                            continue;
                        }
                    }
                }
                MessageType::Snapshot => {
                    match msg.parse_snapshot_public_data() {
                        Ok(pd) => (pd.pub_key, pd.doc_id),
                        Err(e) => {
                            tracing::debug!(error = %e, "e2ee_parse_snapshot_public_data_error");
                            continue;
                        }
                    }
                }
                MessageType::Awareness => {
                    match msg.parse_ephemeral_public_data() {
                        Ok(pd) => (pd.pub_key, pd.doc_id),
                        Err(e) => {
                            tracing::debug!(error = %e, "e2ee_parse_ephemeral_public_data_error");
                            continue;
                        }
                    }
                }
            };

            // Verify document ID matches
            if msg_doc_id != doc_id {
                tracing::warn!(
                    expected = %doc_id,
                    actual = %msg_doc_id,
                    "e2ee_doc_id_mismatch"
                );
                continue;
            }

            // Check edit permission for updates/snapshots
            if !effective_can_edit
                && matches!(msg.msg_type, MessageType::Update | MessageType::Snapshot)
            {
                tracing::debug!("e2ee_write_rejected_readonly");
                continue;
            }

            // Decode signature components
            let public_key = match base64::engine::general_purpose::STANDARD.decode(&pub_key_b64) {
                Ok(k) => k,
                Err(e) => {
                    tracing::debug!(error = %e, "e2ee_public_key_decode_error");
                    continue;
                }
            };
            let signature =
                match base64::engine::general_purpose::STANDARD.decode(&msg.signature) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!(error = %e, "e2ee_signature_decode_error");
                        continue;
                    }
                };

            // Verify Ed25519 signature (secsync format: domain + canonicalize({nonce, ciphertext, publicData}))
            let signing_message = Ed25519Verifier::build_signing_message(
                msg.signature_domain(),
                &msg.nonce,
                &msg.ciphertext,
                &msg.public_data,
            );

            match Ed25519Verifier::verify(&public_key, &signing_message, &signature) {
                Ok(true) => {
                    // Signature valid
                }
                Ok(false) => {
                    tracing::warn!(
                        document_id = %doc_id,
                        "e2ee_signature_invalid"
                    );
                    continue;
                }
                Err(e) => {
                    tracing::warn!(
                        document_id = %doc_id,
                        error = %e,
                        "e2ee_signature_verify_error"
                    );
                    continue;
                }
            }

            // Decode ciphertext and nonce for persistence
            let ciphertext =
                match base64::engine::general_purpose::STANDARD.decode(&msg.ciphertext) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::debug!(error = %e, "e2ee_ciphertext_decode_error");
                        continue;
                    }
                };
            let nonce = match base64::engine::general_purpose::STANDARD.decode(&msg.nonce) {
                Ok(n) => n,
                Err(e) => {
                    tracing::debug!(error = %e, "e2ee_nonce_decode_error");
                    continue;
                }
            };

            // Process message by type
            match msg.msg_type {
                MessageType::Update => {
                    // Persist encrypted update
                    if let Err(e) = self
                        .apply_encrypted_update(
                            doc_id,
                            &ciphertext,
                            Some(&nonce),
                            Some(&signature),
                            Some(&public_key),
                        )
                        .await
                    {
                        tracing::warn!(error = %e, "e2ee_persist_update_failed");
                    }
                }
                MessageType::Snapshot => {
                    // Persist encrypted snapshot
                    if let Err(e) = self
                        .apply_encrypted_snapshot(doc_id, &ciphertext, Some(&nonce), Some(&signature))
                        .await
                    {
                        tracing::warn!(error = %e, "e2ee_persist_snapshot_failed");
                    }
                }
                MessageType::Awareness => {
                    // Awareness messages are ephemeral, no persistence
                }
            }

            // Relay to other clients
            room.broadcast_except(&data, &sink).await;
        }

        // Remove client from room
        room.remove_client(&sink).await;

        let remaining = room.client_count().await;
        tracing::debug!(
            document_id = %doc_id,
            remaining_clients = remaining,
            "e2ee_client_disconnected"
        );

        Ok(())
    }

    async fn ensure_edit_flag(&self, doc_id: &str) -> Arc<AtomicBool> {
        let mut guard = self.edit_flags.write().await;
        guard
            .entry(doc_id.to_string())
            .or_insert_with(|| Arc::new(AtomicBool::new(true)))
            .clone()
    }

    pub async fn set_document_editable(&self, doc_id: &str, editable: bool) -> anyhow::Result<()> {
        let flag = self.ensure_edit_flag(doc_id).await;
        flag.store(editable, Ordering::SeqCst);
        Ok(())
    }
}
