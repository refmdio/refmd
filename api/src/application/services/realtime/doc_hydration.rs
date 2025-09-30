use std::sync::Arc;

use anyhow::Context;
use tokio::task;
use uuid::Uuid;
use yrs::encoding::read::Cursor;
use yrs::sync::{Message, MessageReader, SyncMessage};
use yrs::updates::decoder::{Decode, DecoderV1};
use yrs::{Doc, Transact, Update};

use crate::application::ports::realtime_hydration_port::{DocStateReader, RealtimeBacklogReader};
use crate::application::ports::storage_port::StoragePort;

pub struct DocHydrationService {
    state_reader: Arc<dyn DocStateReader>,
    backlog_reader: Arc<dyn RealtimeBacklogReader>,
    storage: Arc<dyn StoragePort>,
}

pub struct HydrationOptions<'a> {
    pub update_start_id: Option<&'a str>,
    pub awareness_start_id: Option<&'a str>,
    pub read_storage_if_empty: bool,
}

impl Default for HydrationOptions<'_> {
    fn default() -> Self {
        Self {
            update_start_id: None,
            awareness_start_id: None,
            read_storage_if_empty: true,
        }
    }
}

impl DocHydrationService {
    pub fn new(
        state_reader: Arc<dyn DocStateReader>,
        backlog_reader: Arc<dyn RealtimeBacklogReader>,
        storage: Arc<dyn StoragePort>,
    ) -> Self {
        Self {
            state_reader,
            backlog_reader,
            storage,
        }
    }

    pub async fn hydrate(
        &self,
        doc_id: &Uuid,
        options: HydrationOptions<'_>,
    ) -> anyhow::Result<HydratedDoc> {
        let doc = Doc::new();
        let mut last_seq = 0i64;
        let mut last_update_stream_id: Option<String> = None;
        let mut last_awareness_stream_id: Option<String> = None;
        let mut awareness_frames = Vec::new();

        if let Some(snapshot) = self.state_reader.latest_snapshot(doc_id).await? {
            let doc_for_snapshot = doc.clone();
            let snapshot_bytes = snapshot.snapshot.clone();
            task::spawn_blocking(move || {
                if let Ok(update) = Update::decode_v1(&snapshot_bytes) {
                    let mut txn = doc_for_snapshot.transact_mut();
                    let _ = txn.apply_update(update);
                }
            })
            .await
            .context("hydrate_apply_snapshot_join")?;
            last_seq = snapshot.version;
        }

        let updates = self.state_reader.updates_since(doc_id, last_seq).await?;

        for update in updates {
            if update.seq > last_seq {
                apply_update_bytes(&doc, &update.update)?;
                last_seq = update.seq;
            }
        }

        let doc_id_str = doc_id.to_string();
        let backlog = self
            .backlog_reader
            .read_update_backlog(&doc_id_str, options.update_start_id)
            .await?;
        for entry in backlog {
            let updates = extract_updates(&entry.payload)?;
            for update in updates {
                let mut txn = doc.transact_mut();
                txn.apply_update(update)?;
            }
            last_update_stream_id = Some(entry.id);
        }

        let awareness_entries = self
            .backlog_reader
            .read_awareness_backlog(&doc_id_str, options.awareness_start_id)
            .await?;
        for entry in awareness_entries {
            awareness_frames.push(entry.payload);
            last_awareness_stream_id = Some(entry.id);
        }

        if options.read_storage_if_empty {
            let txt = doc.get_or_insert_text("content");
            let txn = doc.transact();
            let is_empty = yrs::Text::len(&txt, &txn) == 0;
            drop(txn);

            if is_empty {
                if let Some(record) = self.state_reader.document_record(doc_id).await? {
                    if let Some(path) = record.path {
                        let absolute = self.storage.absolute_from_relative(&path);
                        if let Ok(bytes) = self.storage.read_bytes(absolute.as_path()).await {
                            if let Ok(content) = String::from_utf8(bytes) {
                                let body = strip_frontmatter(&content);
                                let mut txn = doc.transact_mut();
                                yrs::Text::insert(&txt, &mut txn, 0, body);
                            }
                        }
                    }
                }
            }
        }

        Ok(HydratedDoc {
            doc,
            last_seq,
            last_update_stream_id,
            last_awareness_stream_id,
            awareness_frames,
        })
    }
}

pub struct HydratedDoc {
    pub doc: Doc,
    pub last_seq: i64,
    pub last_update_stream_id: Option<String>,
    pub last_awareness_stream_id: Option<String>,
    pub awareness_frames: Vec<Vec<u8>>,
}

impl HydratedDoc {
    pub fn is_empty(&self) -> bool {
        let txt = self.doc.get_or_insert_text("content");
        let txn = self.doc.transact();
        let len = yrs::Text::len(&txt, &txn);
        drop(txn);
        len == 0
    }
}

fn apply_update_bytes(doc: &Doc, bytes: &[u8]) -> anyhow::Result<()> {
    let update = Update::decode_v1(bytes)?;
    let mut txn = doc.transact_mut();
    txn.apply_update(update)?;
    Ok(())
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

fn strip_frontmatter(content: &str) -> &str {
    if content.starts_with("---\n") {
        if let Some(idx) = content[4..].find("\n---\n") {
            let start = 4 + idx + 5;
            &content[start..]
        } else {
            content
        }
    } else {
        content
    }
}
