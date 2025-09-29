use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::{Mutex, RwLock};
use yrs::encoding::write::Write as YWrite;
use yrs::sync::protocol::{MSG_SYNC, MSG_SYNC_UPDATE};
use yrs::updates::encoder::{Encoder, EncoderV1};
use yrs::{Doc, ReadTxn, StateVector, Transact, Update};
// use yrs::Text; // not needed; referencing via fully qualified yrs::Text
use crate::application::ports::storage_port::StoragePort;
use crate::infrastructure::db::PgPool;
use sqlx::Row;
use uuid::Uuid;
use yrs::GetString;
use yrs::updates::decoder::Decode;
use yrs_warp::AwarenessRef;
use yrs_warp::broadcast::BroadcastGroup;

use crate::infrastructure::realtime::{DynRealtimeSink, DynRealtimeStream};

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
    pool: PgPool,
    storage: Arc<dyn StoragePort>,
    save_flags: Arc<Mutex<HashMap<String, bool>>>,
}

impl Hub {
    pub fn new(pool: PgPool, storage: Arc<dyn StoragePort>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            pool,
            storage,
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

        // Persist Yrs updates to DB
        let pool = self.pool.clone();
        let save_flags = self.save_flags.clone();
        let start_seq: i64 = sqlx::query(
            "SELECT COALESCE(MAX(seq), 0) AS max_seq FROM document_updates WHERE document_id = $1",
        )
        .bind(doc_uuid)
        .fetch_optional(&pool)
        .await?
        .and_then(|row| row.try_get::<i64, _>("max_seq").ok())
        .unwrap_or(0);
        let seq = Arc::new(Mutex::new(start_seq));
        // Persist updates through a channel. We'll await send in a spawned task to avoid dropping updates.
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(512);
        let persist_pool = pool.clone();
        let persist_doc = doc_uuid;
        let persist_seq = seq.clone();
        let doc_for_snap = doc.clone();
        tokio::spawn(async move {
            while let Some(bytes) = rx.recv().await {
                let mut guard = persist_seq.lock().await;
                *guard += 1;
                let s = *guard;
                if let Err(e) = sqlx::query(
                    "INSERT INTO document_updates (document_id, seq, update) VALUES ($1, $2, $3)",
                )
                .bind(persist_doc)
                .bind(s)
                .bind(bytes)
                .execute(&persist_pool)
                .await
                {
                    tracing::error!(document_id = %persist_doc, seq = s, error = ?e, "persist_document_update_failed");
                }
                if s % 100 == 0 {
                    let txn = doc_for_snap.transact();
                    let bin = txn.encode_state_as_update_v1(&StateVector::default());
                    drop(txn);
                    if let Err(e) = sqlx::query(
                        "INSERT INTO document_snapshots (document_id, version, snapshot) VALUES ($1, $2, $3)
                         ON CONFLICT (document_id, version) DO UPDATE SET snapshot = EXCLUDED.snapshot"
                    )
                        .bind(persist_doc)
                        .bind(s as i32)
                        .bind(bin)
                        .execute(&persist_pool)
                        .await
                    {
                        tracing::error!(document_id = %persist_doc, version = s, error = ?e, "persist_document_snapshot_failed");
                    }
                }
            }
        });

        let tx_obs = tx.clone();
        let hub_for_save = self.clone();
        let doc_id_str = doc_uuid.to_string();
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
                let pool = pool.clone();
                let doc_id_s = doc_id_str.clone();
                let hub_clone = hub_for_save.clone();
                tokio::spawn(async move {
                    // simple debounce: set flag and sleep; if still set after sleep, run
                    {
                        let mut m = save_flags.lock().await;
                        m.insert(doc_id_s.clone(), true);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
                    let should_run = {
                        let mut m = save_flags.lock().await;
                        m.remove(&doc_id_s).is_some()
                    };
                    if should_run {
                        if let Err(e) = save_doc_to_fs(&pool, &hub_clone, &doc_id_s).await {
                            tracing::error!(document_id = %doc_id_s, error = ?e, "debounced_save_failed");
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
        let pool_h = self.pool.clone();
        let storage_h = self.storage.clone();
        let bcast_h = bcast.clone();
        tokio::spawn(async move {
            tracing::debug!(%doc_uuid, "hydrate:start");
            let mut hydrated = false;
            if let Ok(row_opt) = sqlx::query("SELECT version, snapshot FROM document_snapshots WHERE document_id = $1 ORDER BY version DESC LIMIT 1")
                .bind(doc_uuid)
                .fetch_optional(&pool_h)
                .await {
                if let Some(row) = row_opt {
                    if let Ok::<Vec<u8>, _>(snap) = row.try_get("snapshot") {
                        let doc_c = doc.clone();
                        let version: i64 = row.get::<i32, _>("version") as i64;
                        if let Ok(()) = tokio::task::spawn_blocking(move || {
                            if let Ok(update) = Update::decode_v1(&snap) {
                                let mut txn = doc_c.transact_mut();
                                let _ = txn.apply_update(update);
                            }
                        }).await { hydrated = true; }
                        if let Ok(mut rows) = sqlx::query("SELECT update FROM document_updates WHERE document_id = $1 AND seq > $2 ORDER BY seq ASC")
                            .bind(doc_uuid)
                            .bind(version)
                            .fetch_all(&pool_h).await {
                            let doc_c2 = doc.clone();
                            let _ = tokio::task::spawn_blocking(move || {
                                for r in rows.drain(..) {
                                    if let Ok::<Vec<u8>, _>(bin) = r.try_get("update") {
                                        if let Ok(u) = Update::decode_v1(&bin) {
                                            let mut txn = doc_c2.transact_mut();
                                            let _ = txn.apply_update(u);
                                        }
                                    }
                                }
                            }).await;
                        }
                    }
                }
            }
            if !hydrated {
                if let Ok(mut rows) = sqlx::query(
                    "SELECT update FROM document_updates WHERE document_id = $1 ORDER BY seq ASC",
                )
                .bind(doc_uuid)
                .fetch_all(&pool_h)
                .await
                {
                    let doc_c3 = doc.clone();
                    let res = tokio::task::spawn_blocking(move || {
                        let mut any = false;
                        for r in rows.drain(..) {
                            if let Ok::<Vec<u8>, _>(bin) = r.try_get("update") {
                                if let Ok(u) = Update::decode_v1(&bin) {
                                    let mut txn = doc_c3.transact_mut();
                                    let _ = txn.apply_update(u);
                                    any = true;
                                }
                            }
                        }
                        any
                    })
                    .await
                    .unwrap_or(false);
                    hydrated = hydrated || res;
                }
            }
            if !hydrated {
                // Try to hydrate from existing stored markdown (fallback when DB has no state)
                if let Ok(row) = sqlx::query("SELECT path FROM documents WHERE id = $1")
                    .bind(doc_uuid)
                    .fetch_one(&pool_h)
                    .await
                {
                    if let Ok::<String, _>(rel) = row.try_get("path") {
                        let full = storage_h.absolute_from_relative(&rel);
                        if let Ok(bytes) = storage_h.read_bytes(full.as_path()).await {
                            if let Ok(data) = String::from_utf8(bytes) {
                                // Strip simple frontmatter --- ... ---
                                let content = if data.starts_with("---\n") {
                                    match data[4..].find("\n---\n") {
                                        Some(pos) => data[(4 + pos + 5)..].to_string(),
                                        None => data,
                                    }
                                } else {
                                    data
                                };
                                let txt = doc.get_or_insert_text("content");
                                let mut txn = doc.transact_mut();
                                let l = yrs::Text::len(&txt, &txn);
                                if l > 0 {
                                    yrs::Text::remove_range(&txt, &mut txn, 0, l);
                                }
                                yrs::Text::insert(&txt, &mut txn, 0, &content);
                                hydrated = true;
                            }
                        }
                    }
                }
                if !hydrated {
                    let txt = doc.get_or_insert_text("content");
                    let mut txn = doc.transact_mut();
                    if yrs::Text::len(&txt, &txn) == 0 {
                        yrs::Text::push(&txt, &mut txn, "# New Document\n\nStart typing...");
                    }
                }
            }
            // Proactively broadcast current state so clients connected before hydration receive content
            let txn = doc.transact();
            let bin = txn.encode_state_as_update_v1(&StateVector::default());
            drop(txn);
            let mut enc = EncoderV1::new();
            enc.write_var(MSG_SYNC);
            enc.write_var(MSG_SYNC_UPDATE);
            enc.write_buf(&bin);
            let msg = enc.to_vec();
            tracing::debug!(%doc_uuid, update_len = bin.len(), frame_len = msg.len(), "hydrate:broadcast_state");
            if let Err(e) = bcast_h.broadcast(msg) {
                tracing::debug!(%doc_uuid, error = %e, "hydrate:broadcast_failed");
            }
            tracing::debug!(%doc_uuid, hydrated=%hydrated, "hydrate:complete");
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
            // Take full state (use v1 encoding to match decoder)
            let bin = {
                let txn = room.doc.transact();
                txn.encode_state_as_update_v1(&StateVector::default())
            };
            // Use current seq as version marker
            let version = {
                let guard = room.seq.lock().await;
                *guard as i32
            };
            sqlx::query(
                "INSERT INTO document_snapshots (document_id, version, snapshot) VALUES ($1, $2, $3)
                 ON CONFLICT (document_id, version) DO UPDATE SET snapshot = EXCLUDED.snapshot"
            )
                .bind(doc_uuid).bind(version).bind(bin)
                .execute(&self.pool).await?;
            // GC: keep only last `keep_versions` snapshots
            sqlx::query(
                "DELETE FROM document_snapshots WHERE document_id = $1 AND version NOT IN (
                    SELECT version FROM document_snapshots WHERE document_id = $1 ORDER BY version DESC LIMIT $2
                )"
            )
                .bind(doc_uuid).bind(keep_versions)
                .execute(&self.pool).await?;
            // GC: updates older than (current_seq - window)
            let cutoff = (version as i64 - updates_keep_window).max(0);
            sqlx::query("DELETE FROM document_updates WHERE document_id = $1 AND seq <= $2")
                .bind(doc_uuid)
                .bind(cutoff)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    pub async fn force_save_to_fs(&self, doc_id: &str) -> anyhow::Result<()> {
        save_doc_to_fs(&self.pool, self, doc_id).await
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

async fn save_doc_to_fs(pool: &PgPool, hub: &Hub, doc_id: &str) -> anyhow::Result<()> {
    let uuid = Uuid::parse_str(doc_id)?;
    // Fetch meta
    let row = sqlx::query("SELECT id, owner_id, title, type, path FROM documents WHERE id = $1")
        .bind(uuid)
        .fetch_optional(pool)
        .await?;
    let row = match row {
        Some(r) => r,
        None => return Ok(()),
    };
    let dtype: String = row.get("type");
    if dtype == "folder" {
        return Ok(());
    }
    // Build content with frontmatter (deterministic; avoid timestamp/CRDT metadata)
    let title: String = row.get("title");
    let content = hub.get_content(doc_id).await?.unwrap_or_default();
    let mut formatted = format!("---\nid: {}\ntitle: {}\n---\n\n{}", uuid, title, content);
    if !formatted.ends_with('\n') {
        formatted.push('\n');
    }
    if let Err(e) = hub.storage.sync_doc_paths(uuid).await {
        tracing::debug!(%uuid, error = ?e, "sync_doc_paths_failed");
    }
    let filepath = hub.storage.build_doc_file_path(uuid).await?;
    let formatted_bytes = formatted.into_bytes();
    if let Ok(existing) = hub.storage.read_bytes(filepath.as_path()).await {
        if existing == formatted_bytes {
            return Ok(());
        }
    }
    let owner_id: Uuid = row.get("owner_id");
    hub.storage
        .write_bytes(filepath.as_path(), &formatted_bytes)
        .await?;
    // Update document link graph (best-effort)
    let lg_repo = crate::infrastructure::db::repositories::linkgraph_repository_sqlx::SqlxLinkGraphRepository::new(pool.clone());
    if let Err(e) =
        crate::application::linkgraph::update_document_links(&lg_repo, owner_id, uuid, &content)
            .await
    {
        tracing::debug!(%uuid, error=?e, "update_document_links_failed");
    }
    // Update tags (best-effort)
    let tag_repo = crate::infrastructure::db::repositories::tagging_repository_sqlx::SqlxTaggingRepository::new(pool.clone());
    if let Err(e) = crate::application::services::tagging::update_document_tags(
        &tag_repo, uuid, owner_id, &content,
    )
    .await
    {
        tracing::debug!(%uuid, error=?e, "update_document_tags_failed");
    }
    Ok(())
}
