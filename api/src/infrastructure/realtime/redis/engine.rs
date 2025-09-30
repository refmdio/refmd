use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow};
use futures_util::{SinkExt, StreamExt};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_stream::wrappers::UnboundedReceiverStream;
use uuid::Uuid;
use yrs::encoding::read::Cursor;
use yrs::encoding::write::Write as YWrite;
use yrs::sync::protocol::{MSG_SYNC, MSG_SYNC_UPDATE};
use yrs::sync::{Message, MessageReader, SyncMessage};
use yrs::updates::decoder::DecoderV1;
use yrs::updates::encoder::{Encoder, EncoderV1};
use yrs::{Doc, GetString, ReadTxn, StateVector, Transact};

use crate::application::ports::awareness_port::AwarenessPublisher;
use crate::application::ports::linkgraph_repository::LinkGraphRepository;
use crate::application::ports::realtime_hydration_port::{DocStateReader, RealtimeBacklogReader};
use crate::application::ports::realtime_persistence_port::DocPersistencePort;
use crate::application::ports::realtime_port::RealtimeEngine as RealtimeEngineTrait;
use crate::application::ports::realtime_types::{DynRealtimeSink, DynRealtimeStream};
use crate::application::ports::storage_port::StoragePort;
use crate::application::ports::tagging_repository::TaggingRepository;
use crate::application::services::realtime::awareness::{AwarenessService, encode_awareness_state};
use crate::application::services::realtime::doc_hydration::{
    DocHydrationService, HydrationOptions,
};
use crate::application::services::realtime::snapshot::{SnapshotPersistOptions, SnapshotService};
use crate::bootstrap::config::Config;
use crate::infrastructure::db::PgPool;
use crate::infrastructure::db::repositories::linkgraph_repository_sqlx::SqlxLinkGraphRepository;
use crate::infrastructure::db::repositories::tagging_repository_sqlx::SqlxTaggingRepository;
use crate::infrastructure::realtime::{SqlxDocPersistenceAdapter, SqlxDocStateReader};

use super::cluster_bus::{RedisClusterBus, StreamItem};

pub struct RedisRealtimeEngine {
    bus: Arc<RedisClusterBus>,
    hydration_service: Arc<DocHydrationService>,
    snapshot_service: Arc<SnapshotService>,
    task_debounce: Duration,
    awareness_ttl: Duration,
    _worker: Option<JoinHandle<()>>,
}

impl RedisRealtimeEngine {
    pub fn from_config(
        cfg: &Config,
        pool: PgPool,
        storage: Arc<dyn StoragePort>,
    ) -> anyhow::Result<Self> {
        let redis_url = cfg
            .redis_url
            .as_deref()
            .context("redis_url_missing_for_cluster_engine")?;
        let client = redis::Client::open(redis_url)?;
        let bus = Arc::new(RedisClusterBus::new(
            client,
            cfg.redis_stream_prefix.clone(),
            Some(cfg.redis_stream_max_len),
            Duration::from_millis(cfg.redis_task_debounce_ms),
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
        let snapshot_service = Arc::new(SnapshotService::new(
            doc_state_reader,
            doc_persistence,
            storage.clone(),
            linkgraph_repo,
            tagging_repo,
        ));

        let trim_lifetime = if cfg.redis_min_message_lifetime_ms > 0 {
            Some(Duration::from_millis(cfg.redis_min_message_lifetime_ms))
        } else {
            None
        };

        let worker = spawn_persistence_worker(
            cfg,
            bus.clone(),
            hydration_service.clone(),
            snapshot_service.clone(),
            trim_lifetime,
        );

        Ok(Self {
            bus,
            hydration_service,
            snapshot_service,
            task_debounce: Duration::from_millis(cfg.redis_task_debounce_ms),
            awareness_ttl: Duration::from_millis(cfg.redis_awareness_ttl_ms),
            _worker: worker,
        })
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
}

#[async_trait::async_trait]
impl RealtimeEngineTrait for RedisRealtimeEngine {
    async fn subscribe(
        &self,
        doc_id: &str,
        sink: DynRealtimeSink,
        mut stream: DynRealtimeStream,
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

            while let Some(frame) = stream.next().await {
                match frame {
                    Ok(bytes) => match analyse_frame(&bytes) {
                        Ok(summary) => {
                            if summary.has_update {
                                if !can_edit {
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
}

fn analyse_frame(frame: &[u8]) -> anyhow::Result<FrameSummary> {
    let mut decoder = DecoderV1::new(Cursor::new(frame));
    let mut reader = MessageReader::new(&mut decoder);
    let mut summary = FrameSummary::default();
    while let Some(message) = reader.next() {
        match message? {
            Message::Sync(SyncMessage::Update(_)) | Message::Sync(SyncMessage::SyncStep2(_)) => {
                summary.has_update = true;
            }
            Message::Awareness(_) => {
                summary.has_awareness = true;
            }
            _ => {}
        }
    }
    Ok(summary)
}

#[derive(Default)]
struct FrameSummary {
    has_update: bool,
    has_awareness: bool,
}

fn spawn_persistence_worker(
    cfg: &Config,
    bus: Arc<RedisClusterBus>,
    hydration_service: Arc<DocHydrationService>,
    snapshot_service: Arc<SnapshotService>,
    trim_lifetime: Option<Duration>,
) -> Option<JoinHandle<()>> {
    if !cfg.cluster_mode {
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
                            if let Err(e) = snapshot_service
                                .persist_snapshot(
                                    &doc_uuid,
                                    &hydrated.doc,
                                    SnapshotPersistOptions {
                                        clear_updates: true,
                                        ..Default::default()
                                    },
                                )
                                .await
                            {
                                tracing::error!(
                                    document_id = %doc_uuid,
                                    error = ?e,
                                    "redis_worker_snapshot_failed"
                                );
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
