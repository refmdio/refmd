use std::sync::Arc;

use anyhow::Context;
use futures_util::TryStreamExt;
use sqlx::Row;
use uuid::Uuid;
use yrs::encoding::read::Cursor;
use yrs::sync::{Message, MessageReader, SyncMessage};
use yrs::updates::decoder::{Decode, DecoderV1};
use yrs::{Doc, Transact, Update};

use super::cluster_bus::RedisClusterBus;
use crate::application::ports::storage_port::StoragePort;
use crate::infrastructure::db::PgPool;

pub struct HydratedDoc {
    pub doc: Doc,
    pub last_seq: i64,
    pub last_update_stream_id: Option<String>,
    pub last_awareness_stream_id: Option<String>,
    pub awareness_frames: Vec<Vec<u8>>,
}

#[derive(Clone)]
pub struct DocHydrator {
    pool: PgPool,
    storage: Arc<dyn StoragePort>,
    bus: Arc<RedisClusterBus>,
}

impl DocHydrator {
    pub fn new(pool: PgPool, storage: Arc<dyn StoragePort>, bus: Arc<RedisClusterBus>) -> Self {
        Self { pool, storage, bus }
    }

    pub async fn hydrate(&self, doc_id: &Uuid) -> anyhow::Result<HydratedDoc> {
        let doc = Doc::new();
        let mut last_seq = 0i64;
        let pool = self.pool.clone();
        let mut last_update_id: Option<String> = None;
        let mut last_awareness_id: Option<String> = None;
        let mut awareness_frames = Vec::new();
        let doc_id_str = doc_id.to_string();

        if let Some(row) = sqlx::query(
            "SELECT version, snapshot FROM document_snapshots WHERE document_id = $1 ORDER BY version DESC LIMIT 1",
        )
        .bind(doc_id)
        .fetch_optional(&pool)
        .await? {
            let version: i32 = row.get("version");
            if let Ok::<Vec<u8>, _>(snapshot) = row.try_get("snapshot") {
                let target = doc.clone();
                tokio::task::spawn_blocking(move || {
                    if let Ok(update) = Update::decode_v1(&snapshot) {
                        let mut txn = target.transact_mut();
                        let _ = txn.apply_update(update);
                    }
                })
                .await
                .context("apply_snapshot")?;
                last_seq = version as i64;
            }
        }

        if last_seq >= 0 {
            let mut rows = sqlx::query(
                "SELECT seq, update FROM document_updates WHERE document_id = $1 AND seq > $2 ORDER BY seq ASC",
            )
            .bind(doc_id)
            .bind(last_seq)
            .fetch(&pool);

            while let Some(row) = rows.try_next().await? {
                if let Ok::<Vec<u8>, _>(bin) = row.try_get("update") {
                    if let Ok(u) = Update::decode_v1(&bin) {
                        let mut txn = doc.transact_mut();
                        txn.apply_update(u)?;
                    }
                }
                let seq: i64 = row.get("seq");
                if seq > last_seq {
                    last_seq = seq;
                }
            }
        }

        let backlog = self.bus.read_update_backlog(&doc_id_str, None).await?;
        for (entry_id, frame) in backlog {
            let updates = extract_updates(&frame)?;
            for update in updates {
                let mut txn = doc.transact_mut();
                txn.apply_update(update)?;
            }
            last_update_id = Some(entry_id);
        }

        let awareness_backlog = self.bus.read_awareness_backlog(&doc_id_str, None).await?;
        for (entry_id, payload) in awareness_backlog {
            awareness_frames.push(payload);
            last_awareness_id = Some(entry_id);
        }

        let txt = doc.get_or_insert_text("content");
        let txn = doc.transact();
        let is_empty = yrs::Text::len(&txt, &txn) == 0;
        drop(txn);

        if is_empty {
            if let Some(row) = sqlx::query("SELECT path FROM documents WHERE id = $1")
                .bind(doc_id)
                .fetch_optional(&pool)
                .await?
            {
                if let Ok::<String, _>(rel) = row.try_get("path") {
                    let abs = self.storage.absolute_from_relative(&rel);
                    if let Ok(bytes) = self.storage.read_bytes(abs.as_path()).await {
                        if let Ok(content) = String::from_utf8(bytes) {
                            let body = if content.starts_with("---\n") {
                                match content[4..].find("\n---\n") {
                                    Some(idx) => content[(4 + idx + 5)..].to_string(),
                                    None => content,
                                }
                            } else {
                                content
                            };
                            let mut txn = doc.transact_mut();
                            yrs::Text::insert(&txt, &mut txn, 0, &body);
                        }
                    }
                }
            }
        }

        Ok(HydratedDoc {
            doc,
            last_seq,
            last_update_stream_id: last_update_id,
            last_awareness_stream_id: last_awareness_id,
            awareness_frames,
        })
    }
}

fn extract_updates(frame: &[u8]) -> anyhow::Result<Vec<Update>> {
    let mut decoder = DecoderV1::new(Cursor::new(frame));
    let mut reader = MessageReader::new(&mut decoder);
    let mut updates = Vec::new();
    while let Some(message) = reader.next() {
        match message? {
            Message::Sync(SyncMessage::Update(bin))
            | Message::Sync(SyncMessage::SyncStep2(bin)) => {
                let update = Update::decode_v1(&bin)?;
                updates.push(update);
            }
            _ => {}
        }
    }
    Ok(updates)
}
