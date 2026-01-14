use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::anyhow;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_stream::wrappers::UnboundedReceiverStream;
use uuid::Uuid;

use crate::core::crypto::Ed25519Verifier;
use crate::core::db::PgPool;
use crate::documents::db::repositories::document_snapshot_archive_repository_sqlx::SqlxDocumentSnapshotArchiveRepository;
use crate::documents::db::repositories::linkgraph_repository_sqlx::SqlxLinkGraphRepository;
use crate::documents::realtime::{SqlxDocPersistenceAdapter, SqlxDocStateReader};
use application::core::ports::errors::PortResult;
use application::core::ports::storage::storage_port::StorageResolverPort;
use application::core::ports::storage::storage_projection_queue::StorageProjectionQueue;
use application::documents::ports::document_snapshot_archive_repository::DocumentSnapshotArchiveRepository;
use application::documents::ports::linkgraph_repository::LinkGraphRepository;
use application::documents::ports::realtime::realtime_hydration_port::{
    DocStateReader, RealtimeBacklogReader,
};
use application::documents::ports::realtime::realtime_persistence_port::{
    ContentEncryptionMeta, DocPersistencePort, EncryptedUpdateData,
};
use application::documents::ports::realtime::realtime_port::{
    EncryptedUpdate, RealtimeEngine as RealtimeEngineTrait, SnapshotData,
};
use application::documents::ports::realtime::realtime_types::{
    DynRealtimeSink, DynRealtimeStream, MessageType, RealtimeMessage,
};
use application::documents::services::realtime::doc_hydration::DocHydrationService;
use application::documents::services::realtime::snapshot::SnapshotService;

use super::cluster_bus::{RedisClusterBus, StreamItem};

type SharedRealtimeSink = Arc<Mutex<DynRealtimeSink>>;

pub struct RedisRealtimeEngine {
    bus: Arc<RedisClusterBus>,
    _hydration_service: Arc<DocHydrationService>,
    snapshot_service: Arc<SnapshotService>,
    persistence: Arc<dyn DocPersistencePort>,
    task_debounce: Duration,
    _awareness_ttl: Duration,
    _worker: Option<JoinHandle<()>>,
    edit_flags: Arc<RwLock<HashMap<String, Arc<AtomicBool>>>>,
}

#[derive(Clone, Debug)]
pub struct RedisRealtimeConfig {
    pub redis_url: String,
    pub stream_prefix: String,
    pub stream_max_len: usize,
    pub task_debounce_ms: u64,
    pub min_message_lifetime_ms: u64,
    pub awareness_ttl_ms: u64,
    pub snapshot_archive_interval_secs: u64,
    pub spawn_persistence_worker: bool,
}

impl RedisRealtimeEngine {
    pub fn from_config(
        cfg: RedisRealtimeConfig,
        pool: PgPool,
        storage: Arc<dyn StorageResolverPort>,
        storage_jobs: Arc<dyn StorageProjectionQueue>,
    ) -> anyhow::Result<Self> {
        let client = redis::Client::open(cfg.redis_url.as_str())?;
        let bus = Arc::new(RedisClusterBus::new(
            client,
            cfg.stream_prefix.clone(),
            Some(cfg.stream_max_len),
            Duration::from_millis(cfg.task_debounce_ms),
        ));
        let doc_state_reader: Arc<dyn DocStateReader> =
            Arc::new(SqlxDocStateReader::new(pool.clone()));
        let backlog_reader: Arc<dyn RealtimeBacklogReader> = bus.clone();
        let hydration_service = Arc::new(DocHydrationService::new(
            doc_state_reader.clone(),
            backlog_reader,
            storage.clone(),
        ));

        let doc_persistence: Arc<dyn DocPersistencePort> =
            Arc::new(SqlxDocPersistenceAdapter::new(pool.clone()));
        let linkgraph_repo: Arc<dyn LinkGraphRepository> =
            Arc::new(SqlxLinkGraphRepository::new(pool.clone()));
        let archive_repo: Arc<dyn DocumentSnapshotArchiveRepository> =
            Arc::new(SqlxDocumentSnapshotArchiveRepository::new(pool.clone()));
        let snapshot_service = Arc::new(SnapshotService::new(
            doc_state_reader,
            doc_persistence.clone(),
            linkgraph_repo,
            archive_repo,
            storage_jobs,
        ));
        let trim_lifetime = if cfg.min_message_lifetime_ms > 0 {
            Some(Duration::from_millis(cfg.min_message_lifetime_ms))
        } else {
            None
        };

        // E2EE mode: persistence worker only trims Redis streams
        let worker = spawn_persistence_worker(
            cfg.spawn_persistence_worker,
            bus.clone(),
            trim_lifetime,
        );

        Ok(Self {
            bus,
            _hydration_service: hydration_service,
            snapshot_service,
            persistence: doc_persistence,
            task_debounce: Duration::from_millis(cfg.task_debounce_ms),
            _awareness_ttl: Duration::from_millis(cfg.awareness_ttl_ms),
            _worker: worker,
            edit_flags: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn snapshot_service(&self) -> Arc<SnapshotService> {
        self.snapshot_service.clone()
    }

    /// Spawn a task to forward E2EE messages from Redis to the client
    fn spawn_e2ee_forward_task(
        mut stream: UnboundedReceiverStream<anyhow::Result<StreamItem>>,
        sink: SharedRealtimeSink,
        doc_id: String,
        channel: &'static str,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(item) = stream.next().await {
                match item {
                    Ok((_id, frame)) => {
                        let mut guard = sink.lock().await;
                        if let Err(e) = guard.send(frame).await {
                            tracing::debug!(
                                document_id = %doc_id,
                                channel,
                                error = %e,
                                "redis_e2ee_forward_sink_closed"
                            );
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            document_id = %doc_id,
                            channel,
                            error = ?e,
                            "redis_e2ee_forward_stream_error"
                        );
                    }
                }
            }
        })
    }

    async fn ensure_edit_flag(&self, doc_id: &str) -> Arc<AtomicBool> {
        let mut guard = self.edit_flags.write().await;
        guard
            .entry(doc_id.to_string())
            .or_insert_with(|| Arc::new(AtomicBool::new(true)))
            .clone()
    }

    /// Get the current seq for a document
    async fn get_current_seq(&self, doc_id: &Uuid) -> i64 {
        self.persistence
            .latest_update_seq(doc_id)
            .await
            .ok()
            .flatten()
            .unwrap_or(0)
    }

    /// Apply encrypted snapshot with seq tracking
    async fn apply_encrypted_snapshot(
        &self,
        doc_id: &Uuid,
        data: &[u8],
        nonce: Option<&[u8]>,
        signature: Option<&[u8]>,
    ) -> anyhow::Result<()> {
        let version = self
            .persistence
            .latest_snapshot_version(doc_id)
            .await?
            .unwrap_or(0)
            + 1;

        let current_seq = self.get_current_seq(doc_id).await;

        let encryption_meta = Some(ContentEncryptionMeta {
            nonce: nonce.map(|n| n.to_vec()),
            signature: signature.map(|s| s.to_vec()),
            seq_at_snapshot: Some(current_seq),
        });

        self.persistence
            .persist_snapshot(doc_id, version, data, encryption_meta.as_ref())
            .await
            .map_err(|e| anyhow!("failed to persist encrypted snapshot: {:?}", e))?;

        tracing::debug!(
            document_id = %doc_id,
            version = version,
            seq_at_snapshot = current_seq,
            "redis_e2ee_snapshot_persisted"
        );

        Ok(())
    }

    /// Apply encrypted update with seq tracking
    async fn apply_encrypted_update(
        &self,
        doc_id: &Uuid,
        data: &[u8],
        nonce: Option<&[u8]>,
        signature: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> anyhow::Result<()> {
        let seq = self.get_current_seq(doc_id).await + 1;

        let update_data = EncryptedUpdateData {
            data: data.to_vec(),
            nonce: nonce.map(|n| n.to_vec()),
            signature: signature.map(|s| s.to_vec()),
            public_key: public_key.map(|p| p.to_vec()),
        };

        self.persistence
            .append_encrypted_update_with_seq(doc_id, seq, &update_data)
            .await
            .map_err(|e| anyhow!("failed to persist encrypted update: {:?}", e))?;

        tracing::debug!(
            document_id = %doc_id,
            seq = seq,
            "redis_e2ee_update_persisted"
        );

        Ok(())
    }
}

#[async_trait::async_trait]
impl RealtimeEngineTrait for RedisRealtimeEngine {
    /// Subscribe to a document for E2EE realtime collaboration via Redis
    ///
    /// This method:
    /// 1. Sends initial encrypted snapshot to the client
    /// 2. Processes incoming E2EE messages (JSON format)
    /// 3. Verifies Ed25519 signatures
    /// 4. Relays valid messages to other clients via Redis
    /// 5. Persists encrypted updates to the database
    async fn subscribe(
        &self,
        doc_id: &str,
        sink: DynRealtimeSink,
        stream: DynRealtimeStream,
        can_edit: bool,
    ) -> PortResult<()> {
        let sink: SharedRealtimeSink = Arc::new(Mutex::new(sink));
        let doc_uuid = Uuid::parse_str(doc_id).map_err(anyhow::Error::from)?;
        let edit_flag = self.ensure_edit_flag(doc_id).await;
        let effective_can_edit = can_edit && edit_flag.load(Ordering::Relaxed);

        let mut updates_handle: Option<JoinHandle<()>> = None;
        let mut awareness_handle: Option<JoinHandle<()>> = None;

        let result: anyhow::Result<()> = async {
            // Send initial encrypted snapshot if available
            let snapshot_seq = if let Ok(Some(entry)) =
                self.persistence.latest_snapshot_entry(&doc_uuid).await
            {
                let init_msg = serde_json::json!({
                    "type": "init",
                    "snapshot": {
                        "data": base64::engine::general_purpose::STANDARD.encode(&entry.bytes),
                        "nonce": entry.nonce.map(|n| base64::engine::general_purpose::STANDARD.encode(&n)),
                        "signature": entry.signature.map(|s| base64::engine::general_purpose::STANDARD.encode(&s)),
                        "seq_at_snapshot": entry.seq_at_snapshot,
                    }
                });
                let msg_bytes = serde_json::to_vec(&init_msg)?;
                let mut guard = sink.lock().await;
                if let Err(e) = guard.send(msg_bytes).await {
                    tracing::debug!(error = %e, "redis_e2ee_init_send_failed");
                }
                drop(guard);
                entry.seq_at_snapshot.unwrap_or(0)
            } else {
                0
            };

            // Send pending encrypted updates since last snapshot
            tracing::info!(
                document_id = %doc_uuid,
                snapshot_seq = snapshot_seq,
                "redis_e2ee_loading_updates_since"
            );
            if let Ok(updates) = self
                .persistence
                .get_updates_since(&doc_uuid, snapshot_seq)
                .await
            {
                tracing::info!(
                    document_id = %doc_uuid,
                    update_count = updates.len(),
                    "redis_e2ee_sending_sync_updates"
                );
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
                        tracing::debug!(error = %e, "redis_e2ee_sync_update_send_failed");
                        break;
                    }
                    tracing::debug!(
                        document_id = %doc_uuid,
                        seq = update.seq,
                        "redis_e2ee_sync_update_sent"
                    );
                    drop(guard);
                }
            }

            // Subscribe to Redis streams for updates from other clients
            let updates_stream = self.bus.subscribe_updates(doc_id, None).await?;
            let awareness_stream = self.bus.subscribe_awareness(doc_id, None).await?;

            updates_handle = Some(Self::spawn_e2ee_forward_task(
                updates_stream,
                sink.clone(),
                doc_id.to_string(),
                "updates",
            ));
            awareness_handle = Some(Self::spawn_e2ee_forward_task(
                awareness_stream,
                sink.clone(),
                doc_id.to_string(),
                "awareness",
            ));

            // Process incoming E2EE messages
            let mut stream = stream;
            while let Some(result) = stream.next().await {
                let data = match result {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::debug!(error = %e, "redis_e2ee_stream_error");
                        break;
                    }
                };

                // Parse E2EE message (secsync-compatible format)
                tracing::info!(
                    document_id = %doc_id,
                    data_len = data.len(),
                    "redis_e2ee_received_message"
                );
                let msg: RealtimeMessage = match serde_json::from_slice(&data) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::warn!(error = %e, data_preview = %String::from_utf8_lossy(&data[..data.len().min(200)]), "redis_e2ee_parse_error");
                        continue;
                    }
                };

                // Extract public key from publicData based on message type
                let (pub_key_b64, msg_doc_id) = match msg.msg_type {
                    MessageType::Update => match msg.parse_update_public_data() {
                        Ok(pd) => (pd.pub_key, pd.doc_id),
                        Err(e) => {
                            tracing::debug!(error = %e, "redis_e2ee_parse_update_public_data_error");
                            continue;
                        }
                    },
                    MessageType::Snapshot => match msg.parse_snapshot_public_data() {
                        Ok(pd) => (pd.pub_key, pd.doc_id),
                        Err(e) => {
                            tracing::debug!(error = %e, "redis_e2ee_parse_snapshot_public_data_error");
                            continue;
                        }
                    },
                    MessageType::Awareness => match msg.parse_ephemeral_public_data() {
                        Ok(pd) => (pd.pub_key, pd.doc_id),
                        Err(e) => {
                            tracing::debug!(error = %e, "redis_e2ee_parse_ephemeral_public_data_error");
                            continue;
                        }
                    },
                };

                // Verify document ID matches
                if msg_doc_id != doc_id {
                    tracing::warn!(
                        expected = %doc_id,
                        actual = %msg_doc_id,
                        "redis_e2ee_doc_id_mismatch"
                    );
                    continue;
                }

                // Check edit permission for updates/snapshots
                if !effective_can_edit
                    && matches!(msg.msg_type, MessageType::Update | MessageType::Snapshot)
                {
                    tracing::debug!("redis_e2ee_write_rejected_readonly");
                    continue;
                }

                // Decode signature components
                let public_key =
                    match base64::engine::general_purpose::STANDARD.decode(&pub_key_b64) {
                        Ok(k) => k,
                        Err(e) => {
                            tracing::debug!(error = %e, "redis_e2ee_public_key_decode_error");
                            continue;
                        }
                    };
                let signature =
                    match base64::engine::general_purpose::STANDARD.decode(&msg.signature) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::debug!(error = %e, "redis_e2ee_signature_decode_error");
                            continue;
                        }
                    };

                // Verify Ed25519 signature
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
                            "redis_e2ee_signature_invalid"
                        );
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(
                            document_id = %doc_id,
                            error = %e,
                            "redis_e2ee_signature_verify_error"
                        );
                        continue;
                    }
                }

                // Decode ciphertext and nonce for persistence
                let ciphertext =
                    match base64::engine::general_purpose::STANDARD.decode(&msg.ciphertext) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::debug!(error = %e, "redis_e2ee_ciphertext_decode_error");
                            continue;
                        }
                    };
                let nonce = match base64::engine::general_purpose::STANDARD.decode(&msg.nonce) {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::debug!(error = %e, "redis_e2ee_nonce_decode_error");
                        continue;
                    }
                };

                // Process message by type
                let persist_error: Option<String> = match msg.msg_type {
                    MessageType::Update => {
                        // Persist encrypted update
                        tracing::info!(
                            document_id = %doc_id,
                            ciphertext_len = ciphertext.len(),
                            nonce_len = nonce.len(),
                            signature_len = signature.len(),
                            public_key_len = public_key.len(),
                            "redis_e2ee_persisting_update"
                        );
                        match self
                            .apply_encrypted_update(
                                &doc_uuid,
                                &ciphertext,
                                Some(&nonce),
                                Some(&signature),
                                Some(&public_key),
                            )
                            .await
                        {
                            Ok(_) => {
                                tracing::info!(document_id = %doc_id, "redis_e2ee_update_persisted_ok");
                                None
                            }
                            Err(e) => {
                                tracing::error!(
                                    document_id = %doc_id,
                                    error = %e,
                                    error_debug = ?e,
                                    "redis_e2ee_persist_update_failed"
                                );
                                Some(format!("Failed to persist update: {}", e))
                            }
                        }
                    }
                    MessageType::Snapshot => {
                        // Persist encrypted snapshot
                        match self
                            .apply_encrypted_snapshot(
                                &doc_uuid,
                                &ciphertext,
                                Some(&nonce),
                                Some(&signature),
                            )
                            .await
                        {
                            Ok(_) => None,
                            Err(e) => {
                                tracing::error!(
                                    document_id = %doc_id,
                                    error = %e,
                                    error_debug = ?e,
                                    "redis_e2ee_persist_snapshot_failed"
                                );
                                Some(format!("Failed to persist snapshot: {}", e))
                            }
                        }
                    }
                    MessageType::Awareness => {
                        // Awareness messages are ephemeral, no persistence
                        None
                    }
                };

                // Send error response to client if persistence failed
                if let Some(error_msg) = persist_error {
                    let error_response = serde_json::json!({
                        "type": "error",
                        "error": error_msg,
                        "document_id": doc_id,
                    });
                    if let Ok(error_bytes) = serde_json::to_vec(&error_response) {
                        let mut guard = sink.lock().await;
                        if let Err(e) = guard.send(error_bytes).await {
                            tracing::debug!(error = %e, "redis_e2ee_error_response_send_failed");
                        }
                    }
                }

                // Relay to other clients via Redis
                match msg.msg_type {
                    MessageType::Update | MessageType::Snapshot => {
                        if let Err(e) = self.bus.publish_update(doc_id, data.clone()).await {
                            tracing::warn!(
                                document_id = %doc_id,
                                error = ?e,
                                "redis_e2ee_publish_update_failed"
                            );
                            sleep(self.task_debounce).await;
                        }
                    }
                    MessageType::Awareness => {
                        if let Err(e) = self.bus.publish_awareness(doc_id, data.clone()).await {
                            tracing::debug!(
                                document_id = %doc_id,
                                error = ?e,
                                "redis_e2ee_publish_awareness_failed"
                            );
                        }
                    }
                }
            }

            Ok(())
        }
        .await;

        if let Some(handle) = updates_handle {
            handle.abort();
        }
        if let Some(handle) = awareness_handle {
            handle.abort();
        }

        tracing::debug!(
            document_id = %doc_id,
            "redis_e2ee_client_disconnected"
        );

        result.map_err(Into::into)
    }

    async fn get_content(&self, _doc_id: &str) -> PortResult<Option<String>> {
        // In E2EE mode, server cannot decrypt content
        Ok(None)
    }

    async fn get_snapshot(&self, doc_id: &str) -> PortResult<Option<SnapshotData>> {
        let uuid = Uuid::parse_str(doc_id).map_err(anyhow::Error::from)?;

        // Get encrypted snapshot from persistence (E2EE mode)
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

    async fn force_persist(&self, doc_id: &str) -> PortResult<()> {
        // In E2EE mode, server cannot write plaintext markdown
        // Snapshot persistence is handled by clients via WebSocket
        tracing::warn!(
            document_id = %doc_id,
            "force_persist called in E2EE mode - server cannot decrypt content"
        );
        Ok(())
    }

    async fn apply_snapshot(&self, doc_id: &str, _snapshot: &[u8]) -> PortResult<()> {
        // In E2EE mode, plaintext snapshot application is not supported
        // Use apply_encrypted_updates or WebSocket snapshot messages instead
        tracing::warn!(
            document_id = %doc_id,
            "apply_snapshot called in E2EE mode - not supported"
        );
        Err(application::core::ports::errors::PortError::from(
            anyhow!("apply_snapshot not available in E2EE mode"),
        ))
    }

    async fn set_document_editable(&self, doc_id: &str, editable: bool) -> PortResult<()> {
        let flag = self.ensure_edit_flag(doc_id).await;
        flag.store(editable, Ordering::SeqCst);
        Ok(())
    }

    async fn apply_encrypted_updates(
        &self,
        doc_id: &str,
        updates: &[EncryptedUpdate],
    ) -> PortResult<()> {
        use application::documents::ports::realtime::realtime_persistence_port::EncryptedUpdateData;

        let doc_uuid = Uuid::parse_str(doc_id).map_err(anyhow::Error::from)?;

        // Get current seq from persistence
        let mut seq = self
            .persistence
            .latest_update_seq(&doc_uuid)
            .await?
            .unwrap_or(0);

        // Store each encrypted update
        for update in updates {
            seq += 1;
            let update_data = EncryptedUpdateData {
                data: update.data.clone(),
                nonce: update.nonce.clone(),
                signature: update.signature.clone(),
                public_key: update.public_key.clone(),
            };

            self.persistence
                .append_encrypted_update_with_seq(&doc_uuid, seq, &update_data)
                .await
                .map_err(|e| {
                    application::core::ports::errors::PortError::from(anyhow::anyhow!(
                        "failed to persist encrypted update: {:?}",
                        e
                    ))
                })?;
        }

        Ok(())
    }

    async fn get_updates_since(
        &self,
        doc_id: &str,
        since_seq: i64,
    ) -> PortResult<Vec<application::documents::ports::realtime::realtime_port::EncryptedUpdateEntry>>
    {
        use application::documents::ports::realtime::realtime_port::EncryptedUpdateEntry;

        let uuid = Uuid::parse_str(doc_id).map_err(anyhow::Error::from)?;

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
}

/// E2EE persistence worker - only trims Redis streams
///
/// In E2EE mode, the server is a relay only:
/// - Snapshots are created by clients (shouldSendSnapshot)
/// - Updates are stored encrypted via WebSocket handler
/// - Markdown rendering is done client-side
///
/// This worker only:
/// 1. Acknowledges tasks from Redis
/// 2. Trims old messages from Redis streams
fn spawn_persistence_worker(
    enabled: bool,
    bus: Arc<RedisClusterBus>,
    trim_lifetime: Option<Duration>,
) -> Option<JoinHandle<()>> {
    if !enabled {
        return None;
    }

    Some(tokio::spawn(async move {
        tracing::info!("redis_persistence_worker_started");
        let mut tasks = match bus.subscribe_tasks(None).await {
            Ok(stream) => stream,
            Err(e) => {
                tracing::error!(error = ?e, "redis_worker_subscribe_tasks_failed");
                return;
            }
        };

        while let Some(task) = tasks.next().await {
            match task {
                Ok((entry_id, doc_id_str)) => {
                    // E2EE mode: just ack the task and trim Redis streams
                    let _ = bus.ack_task(&entry_id).await;

                    if let Some(lifetime) = trim_lifetime {
                        let cutoff = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as i64
                            - lifetime.as_millis() as i64;
                        if cutoff > 0 {
                            let min_id = format!("{}-0", cutoff);
                            let _ = bus.trim_updates_minid(&doc_id_str, &min_id).await;
                            let _ = bus.trim_awareness_minid(&doc_id_str, &min_id).await;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = ?e, "redis_worker_stream_error");
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }

        tracing::info!("redis_persistence_worker_stopped");
    }))
}
