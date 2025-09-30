use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{Duration, sleep};
use uuid::Uuid;
use yrs::GetString;
use yrs::encoding::write::Write as YWrite;
use yrs::sync::protocol::{MSG_SYNC, MSG_SYNC_UPDATE};
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::{Encoder, EncoderV1};
use yrs::{Doc, ReadTxn, StateVector, Transact, Update};
use yrs_warp::AwarenessRef;
use yrs_warp::broadcast::BroadcastGroup;

use crate::application::ports::linkgraph_repository::LinkGraphRepository;
use crate::application::ports::realtime_hydration_port::{DocStateReader, RealtimeBacklogReader};
use crate::application::ports::realtime_persistence_port::DocPersistencePort;
use crate::application::ports::storage_port::StoragePort;
use crate::application::ports::tagging_repository::TaggingRepository;
use crate::application::services::realtime::doc_hydration::{
    DocHydrationService, HydrationOptions,
};
use crate::application::services::realtime::snapshot::{SnapshotPersistOptions, SnapshotService};
use crate::infrastructure::db::PgPool;
use crate::infrastructure::db::repositories::linkgraph_repository_sqlx::SqlxLinkGraphRepository;
use crate::infrastructure::db::repositories::tagging_repository_sqlx::SqlxTaggingRepository;
use crate::infrastructure::realtime::{
    DynRealtimeSink, DynRealtimeStream, NoopBacklogReader, SqlxDocPersistenceAdapter,
    SqlxDocStateReader,
};

#[derive(Clone)]
pub struct DocumentRoom {
    pub doc: Doc,
    pub awareness: AwarenessRef,
    pub broadcast: Arc<BroadcastGroup>,
    #[allow(dead_code)]
    persist_sub: yrs::Subscription,
    pub seq: Arc<Mutex<i64>>, // latest persisted seq
}

#[derive(Clone)]
pub struct Hub {
    inner: Arc<RwLock<HashMap<String, Arc<DocumentRoom>>>>,
    hydration_service: Arc<DocHydrationService>,
    snapshot_service: Arc<SnapshotService>,
    persistence: Arc<dyn DocPersistencePort>,
    save_flags: Arc<Mutex<HashMap<String, bool>>>,
}

impl Hub {
    pub fn new(pool: PgPool, storage: Arc<dyn StoragePort>) -> Self {
        let doc_state_reader: Arc<dyn DocStateReader> =
            Arc::new(SqlxDocStateReader::new(pool.clone()));
        let backlog_reader: Arc<dyn RealtimeBacklogReader> = Arc::new(NoopBacklogReader::default());
        let hydration_service = Arc::new(DocHydrationService::new(
            doc_state_reader.clone(),
            backlog_reader,
            storage.clone(),
        ));
        let persistence: Arc<dyn DocPersistencePort> =
            Arc::new(SqlxDocPersistenceAdapter::new(pool.clone()));
        let linkgraph_repo: Arc<dyn LinkGraphRepository> =
            Arc::new(SqlxLinkGraphRepository::new(pool.clone()));
        let tagging_repo: Arc<dyn TaggingRepository> = Arc::new(SqlxTaggingRepository::new(pool));
        let snapshot_service = Arc::new(SnapshotService::new(
            doc_state_reader,
            persistence.clone(),
            storage,
            linkgraph_repo,
            tagging_repo,
        ));

        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            hydration_service,
            snapshot_service,
            persistence,
            save_flags: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    pub async fn get_or_create(&self, doc_id: &str) -> anyhow::Result<Arc<DocumentRoom>> {
        if let Some(r) = self.inner.read().await.get(doc_id).cloned() {
            return Ok(r);
        }

        // Create Doc; hydration will run asynchronously after room is registered to avoid blocking WS
        let doc = Doc::new();
        let doc_uuid = Uuid::parse_str(doc_id)?;

        let awareness: AwarenessRef = Arc::new(yrs::sync::Awareness::new(doc.clone()));
        let bcast = Arc::new(BroadcastGroup::new(awareness.clone(), 64).await);

        let save_flags = self.save_flags.clone();
        let start_seq = self
            .persistence
            .latest_update_seq(&doc_uuid)
            .await?
            .unwrap_or(0);
        let seq = Arc::new(Mutex::new(start_seq));
        // Persist updates through a channel. We'll await send in a spawned task to avoid dropping updates.
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(512);
        let persistence = self.persistence.clone();
        let snapshot_service = self.snapshot_service.clone();
        let persist_doc = doc_uuid;
        let persist_seq = seq.clone();
        let doc_for_snap = doc.clone();
        tokio::spawn(async move {
            while let Some(bytes) = rx.recv().await {
                let mut guard = persist_seq.lock().await;
                *guard += 1;
                let s = *guard;
                if let Err(e) = persistence
                    .append_update_with_seq(&persist_doc, s, &bytes)
                    .await
                {
                    tracing::error!(
                        document_id = %persist_doc,
                        seq = s,
                        error = ?e,
                        "persist_document_update_failed"
                    );
                }
                if s % 100 == 0 {
                    if let Err(e) = snapshot_service
                        .persist_snapshot(
                            &persist_doc,
                            &doc_for_snap,
                            SnapshotPersistOptions {
                                clear_updates: false,
                                ..Default::default()
                            },
                        )
                        .await
                    {
                        tracing::error!(
                            document_id = %persist_doc,
                            version = s,
                            error = ?e,
                            "persist_document_snapshot_failed"
                        );
                    }
                }
            }
        });

        let tx_obs = tx.clone();
        let hub_for_save = self.clone();
        let doc_id_str = doc_uuid.to_string();
        let doc_for_markdown = doc.clone();
        let persist_sub = doc
            .observe_update_v1(move |_txn, u| {
                // Send to the channel asynchronously to avoid blocking and prevent drops under load
                let tx_clone = tx_obs.clone();
                let bytes = u.update.clone();
                tokio::spawn(async move {
                    let _ = tx_clone.send(bytes).await;
                });
                // schedule fs save (debounced)
                let save_flags = save_flags.clone();
                let doc_id_s = doc_id_str.clone();
                let hub_clone = hub_for_save.clone();
                let doc_for_markdown = doc_for_markdown.clone();
                tokio::spawn(async move {
                    // simple debounce: set flag and sleep; if still set after sleep, run
                    {
                        let mut m = save_flags.lock().await;
                        m.insert(doc_id_s.clone(), true);
                    }
                    sleep(Duration::from_millis(600)).await;
                    let should_run = {
                        let mut m = save_flags.lock().await;
                        m.remove(&doc_id_s).is_some()
                    };
                    if should_run {
                        if let Ok(doc_uuid) = Uuid::parse_str(&doc_id_s) {
                            if let Err(e) = hub_clone
                                .snapshot_service
                                .write_markdown(&doc_uuid, &doc_for_markdown)
                                .await
                            {
                                tracing::error!(
                                    document_id = %doc_id_s,
                                    error = ?e,
                                    "debounced_save_failed"
                                );
                            }
                        }
                    }
                });
            })
            .unwrap();

        let room = Arc::new(DocumentRoom {
            doc: doc.clone(),
            awareness: awareness.clone(),
            broadcast: bcast.clone(),
            persist_sub,
            seq: seq.clone(),
        });
        self.inner
            .write()
            .await
            .insert(doc_id.to_string(), room.clone());
        // Hydrate in background (snapshot + updates). Non-blocking for WS subscription
        let bcast_h = bcast.clone();
        let hydration = self.hydration_service.clone();
        let seq_for_hydrate = seq.clone();
        tokio::spawn(async move {
            tracing::debug!(%doc_uuid, "hydrate:start");
            match hydration
                .hydrate(&doc_uuid, HydrationOptions::default())
                .await
            {
                Ok(hydrated_state) => {
                    let update_bin = {
                        let txn = hydrated_state.doc.transact();
                        txn.encode_state_as_update_v1(&StateVector::default())
                    };
                    if let Ok(update) = Update::decode_v1(&update_bin) {
                        let mut txn = doc.transact_mut();
                        if let Err(e) = txn.apply_update(update) {
                            tracing::debug!(document_id = %doc_uuid, error = ?e, "hydrate_apply_failed");
                        }
                    }

                    if hydrated_state.is_empty() {
                        let txt = doc.get_or_insert_text("content");
                        let mut txn = doc.transact_mut();
                        if yrs::Text::len(&txt, &txn) == 0 {
                            yrs::Text::push(&txt, &mut txn, "# New Document\n\nStart typing...");
                        }
                    }

                    {
                        let mut guard = seq_for_hydrate.lock().await;
                        if hydrated_state.last_seq > *guard {
                            *guard = hydrated_state.last_seq;
                        }
                    }

                    let txn = doc.transact();
                    let bin = txn.encode_state_as_update_v1(&StateVector::default());
                    drop(txn);
                    let mut enc = EncoderV1::new();
                    enc.write_var(MSG_SYNC);
                    enc.write_var(MSG_SYNC_UPDATE);
                    enc.write_buf(&bin);
                    let msg = enc.to_vec();
                    if let Err(e) = bcast_h.broadcast(msg) {
                        tracing::debug!(
                            document_id = %doc_uuid,
                            error = %e,
                            "hydrate:broadcast_failed"
                        );
                    }
                    tracing::debug!(document_id = %doc_uuid, "hydrate:complete");
                }
                Err(e) => {
                    tracing::error!(document_id = %doc_uuid, error = ?e, "hydrate_failed");
                }
            }
        });
        Ok(room)
    }

    pub async fn get_content(&self, doc_id: &str) -> anyhow::Result<Option<String>> {
        let map = self.inner.read().await;
        let room = match map.get(doc_id) {
            Some(room) => room.clone(),
            None => return Ok(None),
        };
        let txt = room.doc.get_or_insert_text("content");
        let txn = room.doc.transact();
        Ok(Some(txt.get_string(&txn)))
    }
}

impl Hub {
    pub async fn snapshot_all(
        &self,
        keep_versions: i64,
        updates_keep_window: i64,
    ) -> anyhow::Result<()> {
        let rooms: Vec<(String, Arc<DocumentRoom>)> = {
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
            self.snapshot_service
                .persist_snapshot(
                    &doc_uuid,
                    &room.doc,
                    SnapshotPersistOptions {
                        clear_updates: false,
                        prune_snapshots: Some(keep_versions),
                        prune_updates_before: Some(cutoff),
                    },
                )
                .await?;
        }
        Ok(())
    }

    pub async fn force_save_to_fs(&self, doc_id: &str) -> anyhow::Result<()> {
        let uuid = Uuid::parse_str(doc_id)?;
        if let Some(room) = self.inner.read().await.get(doc_id).cloned() {
            self.snapshot_service
                .write_markdown(&uuid, &room.doc)
                .await?;
        } else {
            let hydrated = self
                .hydration_service
                .hydrate(&uuid, HydrationOptions::default())
                .await?;
            self.snapshot_service
                .write_markdown(&uuid, &hydrated.doc)
                .await?;
        }
        Ok(())
    }

    pub async fn subscribe(
        &self,
        doc_id: &str,
        sink: DynRealtimeSink,
        stream: DynRealtimeStream,
        can_edit: bool,
    ) -> anyhow::Result<()> {
        let room = self.get_or_create(doc_id).await?;
        let subscription = if can_edit {
            room.broadcast.subscribe(sink, stream)
        } else {
            room.broadcast
                .subscribe_with(sink, stream, ReadOnlyProtocol)
        };

        subscription
            .completed()
            .await
            .map_err(|e| anyhow::anyhow!(e))
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
