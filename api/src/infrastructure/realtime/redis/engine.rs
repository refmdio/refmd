use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use futures_util::{SinkExt, StreamExt};
use sqlx::Row;
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

use crate::application::ports::realtime_port::RealtimeEngine as RealtimeEngineTrait;
use crate::application::ports::realtime_types::{DynRealtimeSink, DynRealtimeStream};
use crate::application::ports::storage_port::StoragePort;
use crate::bootstrap::config::Config;
use crate::infrastructure::db::PgPool;

use super::awareness_manager::{RedisAwarenessManager, encode_awareness_state};
use super::cluster_bus::{RedisClusterBus, StreamItem};
use super::doc_hydrator::DocHydrator;

pub struct RedisRealtimeEngine {
    bus: Arc<RedisClusterBus>,
    hydrator: DocHydrator,
    pool: PgPool,
    storage: Arc<dyn StoragePort>,
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
        let hydrator = DocHydrator::new(pool.clone(), storage.clone(), bus.clone());
        let worker = spawn_persistence_worker(cfg, pool.clone(), storage.clone(), bus.clone());

        Ok(Self {
            bus,
            hydrator,
            pool,
            storage,
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
        awareness_manager: &RedisAwarenessManager,
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
        awareness_manager: Option<RedisAwarenessManager>,
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
        let hydrated = self.hydrator.hydrate(&doc_uuid).await?;
        let awareness_manager = RedisAwarenessManager::new(
            hydrated.doc.clone(),
            self.bus.clone(),
            doc_id.to_string(),
            self.awareness_ttl,
        );
        let ttl_handle = awareness_manager.spawn_ttl_task();
        let mut updates_handle: Option<JoinHandle<()>> = None;
        let mut awareness_handle: Option<JoinHandle<()>> = None;

        let result: anyhow::Result<()> = async {
            self.send_initial_sync(&hydrated.doc, &sink).await?;
            self.flush_awareness_backlog(
                &sink,
                &hydrated.awareness_frames,
                doc_id,
                &awareness_manager,
            )
            .await?;
            if let Ok(Some(frame)) = encode_awareness_state(&awareness_manager.awareness()) {
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
                Some(awareness_manager.clone()),
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
                                awareness_manager.record_local_frame(&bytes).await.ok();
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
        ttl_handle.abort();

        result
    }

    async fn get_content(&self, doc_id: &str) -> anyhow::Result<Option<String>> {
        let uuid = Uuid::parse_str(doc_id)?;
        let hydrated = self.hydrator.hydrate(&uuid).await?;
        let txt = hydrated.doc.get_or_insert_text("content");
        let txn = hydrated.doc.transact();
        Ok(Some(txt.get_string(&txn)))
    }

    async fn force_persist(&self, doc_id: &str) -> anyhow::Result<()> {
        let uuid = Uuid::parse_str(doc_id)?;
        let hydrated = self.hydrator.hydrate(&uuid).await?;
        persist_document_snapshot(&self.pool, &self.storage, &uuid, &hydrated.doc).await
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
    pool: PgPool,
    storage: Arc<dyn StoragePort>,
    bus: Arc<RedisClusterBus>,
) -> Option<JoinHandle<()>> {
    if !cfg.realtime_cluster_mode {
        return None;
    }
    Some(tokio::spawn(async move {
        tracing::info!("redis_persistence_worker_started");
        let hydrator = DocHydrator::new(pool.clone(), storage.clone(), bus.clone());
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
                    Ok(doc_uuid) => match hydrator.hydrate(&doc_uuid).await {
                        Ok(hydrated) => {
                            if let Err(e) =
                                persist_document_snapshot(&pool, &storage, &doc_uuid, &hydrated.doc)
                                    .await
                            {
                                tracing::error!(
                                    document_id = %doc_uuid,
                                    error = ?e,
                                    "redis_worker_persist_failed"
                                );
                            }
                            if let Err(e) = bus.ack_task(&entry_id).await {
                                tracing::debug!(
                                    document_id = %doc_uuid,
                                    error = ?e,
                                    "redis_worker_ack_failed"
                                );
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

async fn persist_document_snapshot(
    pool: &PgPool,
    storage: &Arc<dyn StoragePort>,
    doc_id: &Uuid,
    doc: &Doc,
) -> anyhow::Result<()> {
    let row = sqlx::query("SELECT id, owner_id, title, type, path FROM documents WHERE id = $1")
        .bind(doc_id)
        .fetch_optional(pool)
        .await?
        .context("document_not_found")?;
    let dtype: String = row.get("type");
    if dtype == "folder" {
        return Ok(());
    }
    let title: String = row.get("title");
    let owner_id: Uuid = row.get("owner_id");

    let txt = doc.get_or_insert_text("content");
    let txn = doc.transact();
    let contents = txt.get_string(&txn);
    let snapshot_bin = txn.encode_state_as_update_v1(&StateVector::default());
    drop(txn);

    if let Err(e) = storage.sync_doc_paths(*doc_id).await {
        tracing::debug!(document_id = %doc_id, error = ?e, "redis_cluster_sync_paths_failed");
    }
    let path = storage.build_doc_file_path(*doc_id).await?;
    let mut formatted = format!("---\nid: {}\ntitle: {}\n---\n\n{}", doc_id, title, contents);
    if !formatted.ends_with('\n') {
        formatted.push('\n');
    }
    let bytes = formatted.into_bytes();
    let should_write = match storage.read_bytes(path.as_path()).await {
        Ok(existing) => existing != bytes,
        Err(_) => true,
    };
    if should_write {
        storage.write_bytes(path.as_path(), &bytes).await?;
    }

    let next_version: i64 = sqlx::query(
        "SELECT COALESCE(MAX(version), 0) + 1 AS next FROM document_snapshots WHERE document_id = $1",
    )
    .bind(doc_id)
    .fetch_one(pool)
    .await?
    .get("next");

    sqlx::query(
        "INSERT INTO document_snapshots (document_id, version, snapshot) VALUES ($1, $2, $3)
         ON CONFLICT (document_id, version) DO UPDATE SET snapshot = EXCLUDED.snapshot",
    )
    .bind(doc_id)
    .bind(next_version as i32)
    .bind(&snapshot_bin)
    .execute(pool)
    .await?;

    sqlx::query("DELETE FROM document_updates WHERE document_id = $1")
        .bind(doc_id)
        .execute(pool)
        .await?;

    let lg_repo =
        crate::infrastructure::db::repositories::linkgraph_repository_sqlx::SqlxLinkGraphRepository::new(pool.clone());
    if let Err(e) =
        crate::application::linkgraph::update_document_links(&lg_repo, owner_id, *doc_id, &contents)
            .await
    {
        tracing::debug!(document_id = %doc_id, error = ?e, "redis_cluster_update_links_failed");
    }

    let tag_repo =
        crate::infrastructure::db::repositories::tagging_repository_sqlx::SqlxTaggingRepository::new(pool.clone());
    if let Err(e) = crate::application::services::tagging::update_document_tags(
        &tag_repo, *doc_id, owner_id, &contents,
    )
    .await
    {
        tracing::debug!(document_id = %doc_id, error = ?e, "redis_cluster_update_tags_failed");
    }

    Ok(())
}
