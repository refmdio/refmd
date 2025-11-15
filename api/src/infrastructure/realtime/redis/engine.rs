use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep};
use tokio_stream::wrappers::UnboundedReceiverStream;
use uuid::Uuid;
use yrs::encoding::write::Write as YWrite;
use yrs::sync::awareness::Awareness;
use yrs::sync::protocol::{MSG_SYNC, MSG_SYNC_UPDATE};
use yrs::sync::{DefaultProtocol, Protocol};
use yrs::updates::encoder::{Encoder, EncoderV1};
use yrs::{Doc, GetString, ReadTxn, StateVector, Text, Transact};

use crate::application::ports::awareness_port::AwarenessPublisher;
use crate::application::ports::document_snapshot_archive_repository::DocumentSnapshotArchiveRepository;
use crate::application::ports::linkgraph_repository::LinkGraphRepository;
use crate::application::ports::realtime_hydration_port::{DocStateReader, RealtimeBacklogReader};
use crate::application::ports::realtime_persistence_port::DocPersistencePort;
use crate::application::ports::realtime_port::RealtimeEngine as RealtimeEngineTrait;
use crate::application::ports::realtime_types::{DynRealtimeSink, DynRealtimeStream};
use crate::application::ports::storage_port::StorageResolverPort;
use crate::application::ports::storage_projection_queue::StorageProjectionQueue;
use crate::application::ports::tagging_repository::TaggingRepository;
use crate::application::services::realtime::doc_hydration::{
    DocHydrationService, HydrationOptions,
};
use crate::application::services::realtime::snapshot::{
    SnapshotArchiveKind, SnapshotArchiveOptions, SnapshotPersistOptions, SnapshotService,
    doc_from_snapshot_bytes,
};
use crate::infrastructure::db::PgPool;
use crate::infrastructure::db::repositories::document_snapshot_archive_repository_sqlx::SqlxDocumentSnapshotArchiveRepository;
use crate::infrastructure::db::repositories::linkgraph_repository_sqlx::SqlxLinkGraphRepository;
use crate::infrastructure::db::repositories::tagging_repository_sqlx::SqlxTaggingRepository;
use crate::infrastructure::realtime::awareness::{AwarenessService, encode_awareness_state};
use crate::infrastructure::realtime::utils::{analyse_frame, wrap_stream_with_edit_guard};
use crate::infrastructure::realtime::{SqlxDocPersistenceAdapter, SqlxDocStateReader};

use super::cluster_bus::{RedisClusterBus, StreamItem};

pub struct RedisRealtimeEngine {
    bus: Arc<RedisClusterBus>,
    hydration_service: Arc<DocHydrationService>,
    snapshot_service: Arc<SnapshotService>,
    task_debounce: Duration,
    awareness_ttl: Duration,
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
        let tagging_repo: Arc<dyn TaggingRepository> =
            Arc::new(SqlxTaggingRepository::new(pool.clone()));
        let archive_repo: Arc<dyn DocumentSnapshotArchiveRepository> =
            Arc::new(SqlxDocumentSnapshotArchiveRepository::new(pool.clone()));
        let snapshot_service = Arc::new(SnapshotService::new(
            doc_state_reader,
            doc_persistence,
            linkgraph_repo,
            tagging_repo,
            archive_repo,
            storage_jobs,
        ));
        let auto_archive_interval = Duration::from_secs(cfg.snapshot_archive_interval_secs);
        let last_auto_archive: Arc<Mutex<HashMap<String, Instant>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let trim_lifetime = if cfg.min_message_lifetime_ms > 0 {
            Some(Duration::from_millis(cfg.min_message_lifetime_ms))
        } else {
            None
        };

        let worker = spawn_persistence_worker(
            cfg.spawn_persistence_worker,
            bus.clone(),
            hydration_service.clone(),
            snapshot_service.clone(),
            trim_lifetime,
            auto_archive_interval,
            last_auto_archive.clone(),
        );

        Ok(Self {
            bus,
            hydration_service,
            snapshot_service,
            task_debounce: Duration::from_millis(cfg.task_debounce_ms),
            awareness_ttl: Duration::from_millis(cfg.awareness_ttl_ms),
            _worker: worker,
            edit_flags: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn snapshot_service(&self) -> Arc<SnapshotService> {
        self.snapshot_service.clone()
    }

    async fn send_initial_sync(&self, doc: &Doc, sink: &DynRealtimeSink) -> anyhow::Result<()> {
        let bin = {
            let txn = doc.transact();
            txn.encode_state_as_update_v1(&StateVector::default())
        };
        let mut enc = EncoderV1::new();
        enc.write_var(MSG_SYNC);
        enc.write_var(MSG_SYNC_UPDATE);
        enc.write_buf(&bin);
        let frame = enc.to_vec();

        let mut guard = sink.lock().await;
        guard
            .send(frame)
            .await
            .map_err(|e| anyhow!("initial_sync_send_failed: {e}"))?;
        Ok(())
    }

    async fn flush_awareness_backlog(
        &self,
        sink: &DynRealtimeSink,
        frames: &[Vec<u8>],
        doc_id: &str,
        awareness_manager: &AwarenessService,
    ) -> anyhow::Result<()> {
        for payload in frames {
            awareness_manager.apply_remote_frame(payload).await?;
            let mut guard = sink.lock().await;
            if let Err(e) = guard.send(payload.clone()).await {
                return Err(anyhow!("initial_awareness_send_failed: {e}"));
            }
        }
        tracing::debug!(
            document_id = doc_id,
            count = frames.len(),
            "redis_cluster_awareness_prefill"
        );
        Ok(())
    }

    fn spawn_forward_task(
        mut stream: UnboundedReceiverStream<anyhow::Result<StreamItem>>,
        sink: DynRealtimeSink,
        doc_id: String,
        channel: &'static str,
        awareness_manager: Option<AwarenessService>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(item) = stream.next().await {
                match item {
                    Ok((_id, frame)) => {
                        if let Some(manager) = &awareness_manager {
                            if let Err(e) = manager.apply_remote_frame(&frame).await {
                                tracing::debug!(
                                    document_id = %doc_id,
                                    channel,
                                    error = ?e,
                                    "redis_cluster_awareness_apply_failed"
                                );
                            }
                        }
                        let mut guard = sink.lock().await;
                        if let Err(e) = guard.send(frame).await {
                            tracing::debug!(document_id = %doc_id, channel, error = %e, "redis_cluster_forward_sink_closed");
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(document_id = %doc_id, channel, error = ?e, "redis_cluster_forward_stream_error");
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
}

#[async_trait::async_trait]
impl RealtimeEngineTrait for RedisRealtimeEngine {
    async fn subscribe(
        &self,
        doc_id: &str,
        sink: DynRealtimeSink,
        stream: DynRealtimeStream,
        can_edit: bool,
    ) -> anyhow::Result<()> {
        let doc_uuid = Uuid::parse_str(doc_id)?;
        let hydrated = self
            .hydration_service
            .hydrate(&doc_uuid, HydrationOptions::default())
            .await?;
        let awareness_publisher: Arc<dyn AwarenessPublisher> = self.bus.clone();
        let awareness_service = AwarenessService::new(
            hydrated.doc.clone(),
            self.awareness_ttl,
            awareness_publisher,
            doc_id.to_string(),
        );
        let ttl_handle = awareness_service.spawn_ttl_task();
        let mut updates_handle: Option<JoinHandle<()>> = None;
        let mut awareness_handle: Option<JoinHandle<()>> = None;

        let result: anyhow::Result<()> = async {
            let edit_flag = self.ensure_edit_flag(doc_id).await;
            let session_can_edit = can_edit && edit_flag.load(Ordering::Relaxed);
            let mut guarded_stream =
                wrap_stream_with_edit_guard(stream, doc_id.to_string(), edit_flag.clone());

            self.send_initial_sync(&hydrated.doc, &sink).await?;
            self.flush_awareness_backlog(
                &sink,
                &hydrated.awareness_frames,
                doc_id,
                &awareness_service,
            )
            .await?;
            if let Ok(Some(frame)) = encode_awareness_state(&awareness_service.awareness()) {
                let mut guard = sink.lock().await;
                let _ = guard.send(frame).await;
            }
            Self::send_protocol_start(
                sink.clone(),
                awareness_service.awareness(),
                session_can_edit,
            )
            .await
            .context("redis_cluster_send_protocol_start")?;

            let updates_stream = self
                .bus
                .subscribe_updates(doc_id, hydrated.last_update_stream_id.clone())
                .await?;
            let awareness_stream = self
                .bus
                .subscribe_awareness(doc_id, hydrated.last_awareness_stream_id.clone())
                .await?;

            updates_handle = Some(Self::spawn_forward_task(
                updates_stream,
                sink.clone(),
                doc_id.to_string(),
                "updates",
                None,
            ));
            awareness_handle = Some(Self::spawn_forward_task(
                awareness_stream,
                sink.clone(),
                doc_id.to_string(),
                "awareness",
                Some(awareness_service.clone()),
            ));

            while let Some(frame) = guarded_stream.next().await {
                match frame {
                    Ok(bytes) => match analyse_frame(&bytes) {
                        Ok(summary) => {
                            if summary.has_update {
                                let allow_edit = can_edit && edit_flag.load(Ordering::Relaxed);
                                if !allow_edit {
                                    tracing::warn!(
                                        document_id = %doc_id,
                                        "ignored_update_from_readonly_client"
                                    );
                                } else if let Err(e) =
                                    self.bus.publish_update(doc_id, bytes.clone()).await
                                {
                                    tracing::warn!(
                                        document_id = %doc_id,
                                        error = ?e,
                                        "redis_cluster_publish_update_failed"
                                    );
                                    sleep(self.task_debounce).await;
                                }
                            }
                            if summary.has_awareness {
                                awareness_service.record_local_frame(&bytes).await.ok();
                                if let Err(e) =
                                    self.bus.publish_awareness(doc_id, bytes.clone()).await
                                {
                                    tracing::debug!(
                                        document_id = %doc_id,
                                        error = ?e,
                                        "redis_cluster_publish_awareness_failed"
                                    );
                                }
                            }
                            if !summary.has_update && !summary.has_awareness {
                                tracing::debug!(
                                    document_id = %doc_id,
                                    "redis_cluster_dropped_unknown_frame"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                document_id = %doc_id,
                                error = ?e,
                                "redis_cluster_frame_decode_failed"
                            );
                        }
                    },
                    Err(e) => {
                        tracing::debug!(
                            document_id = %doc_id,
                            error = %e,
                            "redis_cluster_inbound_closed"
                        );
                        break;
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
        if let Err(err) = awareness_service.clear_local_clients().await {
            tracing::debug!(document_id = %doc_id, error = ?err, "redis_cluster_awareness_clear_failed");
        }
        ttl_handle.abort();

        result
    }

    async fn get_content(&self, doc_id: &str) -> anyhow::Result<Option<String>> {
        let uuid = Uuid::parse_str(doc_id)?;
        let hydrated = self
            .hydration_service
            .hydrate(&uuid, HydrationOptions::default())
            .await?;
        let txt = hydrated.doc.get_or_insert_text("content");
        let txn = hydrated.doc.transact();
        Ok(Some(txt.get_string(&txn)))
    }

    async fn force_persist(&self, doc_id: &str) -> anyhow::Result<()> {
        let uuid = Uuid::parse_str(doc_id)?;
        let hydrated = self
            .hydration_service
            .hydrate(&uuid, HydrationOptions::default())
            .await?;
        self.snapshot_service
            .write_markdown(&uuid, &hydrated.doc)
            .await?;
        self.snapshot_service
            .persist_snapshot(
                &uuid,
                &hydrated.doc,
                SnapshotPersistOptions {
                    clear_updates: true,
                    ..Default::default()
                },
            )
            .await?;
        Ok(())
    }

    async fn apply_snapshot(&self, doc_id: &str, snapshot: &[u8]) -> anyhow::Result<()> {
        let doc = doc_from_snapshot_bytes(snapshot)?;
        let uuid = Uuid::parse_str(doc_id)?;
        let hydrated = self
            .hydration_service
            .hydrate(&uuid, HydrationOptions::default())
            .await?;
        let update_bytes = {
            let txt_new = doc.get_or_insert_text("content");
            let txn_new = doc.transact();
            let new_markdown = txt_new.get_string(&txn_new);
            drop(txn_new);

            let txt = hydrated.doc.get_or_insert_text("content");
            let mut txn = hydrated.doc.transact_mut();
            let len = txt.len(&txn);
            if len > 0 {
                txt.remove_range(&mut txn, 0, len);
            }
            if !new_markdown.is_empty() {
                txt.insert(&mut txn, 0, &new_markdown);
            }
            txn.encode_update_v1()
        };
        if update_bytes.is_empty() {
            return Ok(());
        }
        let mut encoder = EncoderV1::new();
        encoder.write_var(MSG_SYNC);
        encoder.write_var(MSG_SYNC_UPDATE);
        encoder.write_buf(&update_bytes);
        let frame = encoder.to_vec();
        self.bus.publish_update(doc_id, frame).await?;
        Ok(())
    }

    async fn set_document_editable(&self, doc_id: &str, editable: bool) -> anyhow::Result<()> {
        let flag = self.ensure_edit_flag(doc_id).await;
        flag.store(editable, Ordering::SeqCst);
        Ok(())
    }
}

fn spawn_persistence_worker(
    enabled: bool,
    bus: Arc<RedisClusterBus>,
    hydration_service: Arc<DocHydrationService>,
    snapshot_service: Arc<SnapshotService>,
    trim_lifetime: Option<Duration>,
    auto_archive_interval: Duration,
    last_auto_archive: Arc<Mutex<HashMap<String, Instant>>>,
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
                Ok((entry_id, doc_id_str)) => match Uuid::parse_str(&doc_id_str) {
                    Ok(doc_uuid) => match hydration_service
                        .hydrate(&doc_uuid, HydrationOptions::default())
                        .await
                    {
                        Ok(hydrated) => {
                            let doc_id_owned = doc_uuid.to_string();
                            if let Err(e) = snapshot_service
                                .write_markdown(&doc_uuid, &hydrated.doc)
                                .await
                            {
                                tracing::error!(
                                    document_id = %doc_uuid,
                                    error = ?e,
                                    "redis_worker_markdown_failed"
                                );
                            }
                            match snapshot_service
                                .persist_snapshot(
                                    &doc_uuid,
                                    &hydrated.doc,
                                    SnapshotPersistOptions {
                                        clear_updates: true,
                                        skip_if_unchanged: true,
                                        ..Default::default()
                                    },
                                )
                                .await
                            {
                                Ok(result) => {
                                    if !auto_archive_interval.is_zero() {
                                        let should_archive = {
                                            let mut guard = last_auto_archive.lock().await;
                                            let now = Instant::now();
                                            match guard.get(&doc_id_owned) {
                                                Some(last)
                                                    if now.duration_since(*last)
                                                        < auto_archive_interval =>
                                                {
                                                    false
                                                }
                                                _ => {
                                                    guard.insert(doc_id_owned.clone(), now);
                                                    true
                                                }
                                            }
                                        };
                                        if should_archive && result.persisted {
                                            let label = format!(
                                                "Snapshot {}",
                                                Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                                            );
                                            if let Err(e) = snapshot_service
                                                .archive_snapshot(
                                                    &doc_uuid,
                                                    &result.snapshot_bytes,
                                                    result.version,
                                                    SnapshotArchiveOptions {
                                                        label: label.as_str(),
                                                        notes: None,
                                                        kind: SnapshotArchiveKind::Automatic,
                                                        created_by: None,
                                                    },
                                                )
                                                .await
                                            {
                                                tracing::debug!(
                                                    document_id = %doc_uuid,
                                                    version = result.version,
                                                    error = ?e,
                                                    "redis_worker_snapshot_archive_failed"
                                                );
                                            }
                                        } else if should_archive {
                                            tracing::debug!(
                                                document_id = %doc_uuid,
                                                version = result.version,
                                                "redis_worker_snapshot_skipped_no_changes"
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(
                                        document_id = %doc_uuid,
                                        error = ?e,
                                        "redis_worker_snapshot_failed"
                                    );
                                }
                            }
                            if let Err(e) = bus.ack_task(&entry_id).await {
                                tracing::debug!(
                                    document_id = %doc_uuid,
                                    error = ?e,
                                    "redis_worker_ack_failed"
                                );
                            }
                            if let Some(lifetime) = trim_lifetime {
                                let cutoff = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis()
                                    as i64
                                    - lifetime.as_millis() as i64;
                                if cutoff > 0 {
                                    let min_id = format!("{}-0", cutoff);
                                    if let Err(e) =
                                        bus.trim_updates_minid(&doc_id_owned, &min_id).await
                                    {
                                        tracing::debug!(
                                            document_id = %doc_uuid,
                                            error = ?e,
                                            "redis_worker_trim_updates_failed"
                                        );
                                    }
                                    if let Err(e) =
                                        bus.trim_awareness_minid(&doc_id_owned, &min_id).await
                                    {
                                        tracing::debug!(
                                            document_id = %doc_uuid,
                                            error = ?e,
                                            "redis_worker_trim_awareness_failed"
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                document_id = %doc_uuid,
                                error = ?e,
                                "redis_worker_hydrate_failed"
                            );
                        }
                    },
                    Err(e) => {
                        tracing::warn!(
                            document_id = %doc_id_str,
                            error = %e,
                            "redis_worker_invalid_doc_id"
                        );
                        let _ = bus.ack_task(&entry_id).await;
                    }
                },
                Err(e) => {
                    tracing::warn!(error = ?e, "redis_worker_stream_error");
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }

        tracing::info!("redis_persistence_worker_stopped");
    }))
}

impl RedisRealtimeEngine {
    async fn send_protocol_start(
        sink: DynRealtimeSink,
        awareness: Arc<Awareness>,
        writable: bool,
    ) -> anyhow::Result<()> {
        let mut encoder = EncoderV1::new();
        if writable {
            DefaultProtocol
                .start::<EncoderV1>(awareness.as_ref(), &mut encoder)
                .map_err(|err| anyhow!(err))?;
        } else {
            ReadOnlyProtocol
                .start::<EncoderV1>(awareness.as_ref(), &mut encoder)
                .map_err(|err| anyhow!(err))?;
        }
        let frame = encoder.to_vec();
        if frame.is_empty() {
            return Ok(());
        }
        let mut guard = sink.lock().await;
        guard.send(frame).await.map_err(|err| anyhow!(err))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct ReadOnlyProtocol;

impl yrs::sync::Protocol for ReadOnlyProtocol {
    fn handle_sync_step2(
        &self,
        _awareness: &yrs::sync::Awareness,
        _update: yrs::Update,
    ) -> Result<Option<yrs::sync::Message>, yrs::sync::Error> {
        Ok(None)
    }

    fn handle_update(
        &self,
        _awareness: &yrs::sync::Awareness,
        _update: yrs::Update,
    ) -> Result<Option<yrs::sync::Message>, yrs::sync::Error> {
        Ok(None)
    }
}
