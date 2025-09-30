use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::sync::Mutex;
use tokio::time::sleep;
use yrs::Doc;
use yrs::block::ClientID;
use yrs::encoding::read::Cursor;
use yrs::sync::awareness::{
    Awareness, AwarenessUpdate, AwarenessUpdateEntry, AwarenessUpdateSummary,
};
use yrs::sync::{Message, MessageReader};
use yrs::updates::decoder::DecoderV1;
use yrs::updates::encoder::Encode;

use crate::application::ports::awareness_port::AwarenessPublisher;

#[derive(Clone)]
pub struct AwarenessService {
    awareness: Arc<Awareness>,
    last_seen: Arc<Mutex<HashMap<ClientID, Instant>>>,
    ttl: Duration,
    publisher: Arc<dyn AwarenessPublisher>,
    doc_id: String,
    local_clients: Arc<Mutex<HashSet<ClientID>>>,
}

impl AwarenessService {
    pub fn new(
        doc: Doc,
        ttl: Duration,
        publisher: Arc<dyn AwarenessPublisher>,
        doc_id: impl Into<String>,
    ) -> Self {
        Self {
            awareness: Arc::new(Awareness::new(doc)),
            last_seen: Arc::new(Mutex::new(HashMap::new())),
            ttl,
            publisher,
            doc_id: doc_id.into(),
            local_clients: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn awareness(&self) -> Arc<Awareness> {
        self.awareness.clone()
    }

    pub async fn apply_remote_frame(&self, frame: &[u8]) -> anyhow::Result<()> {
        self.process_frame(frame, FrameOrigin::Remote).await
    }

    pub async fn record_local_frame(&self, frame: &[u8]) -> anyhow::Result<()> {
        self.process_frame(frame, FrameOrigin::Local).await
    }

    pub async fn clear_local_clients(&self) -> anyhow::Result<()> {
        let clients: Vec<ClientID> = {
            let mut seen = self.last_seen.lock().await;
            let mut locals = self.local_clients.lock().await;
            if locals.is_empty() {
                return Ok(());
            }
            let drained: Vec<ClientID> = locals.drain().collect();
            for client in &drained {
                seen.remove(client);
            }
            drained
        };

        let entries = self.build_null_entries(&clients);
        for client in &clients {
            self.awareness.remove_state(*client);
        }
        if entries.is_empty() {
            return Ok(());
        }

        let update = AwarenessUpdate { clients: entries };
        let frame = Message::Awareness(update).encode_v1();
        self.publisher
            .publish_awareness(&self.doc_id, frame)
            .await
            .context("awareness_publish_local_clear")?;
        Ok(())
    }

    async fn process_frame(&self, frame: &[u8], origin: FrameOrigin) -> anyhow::Result<()> {
        let mut decoder = DecoderV1::new(Cursor::new(frame));
        let mut reader = MessageReader::new(&mut decoder);
        let mut combined = AwarenessUpdateSummary {
            added: Vec::new(),
            updated: Vec::new(),
            removed: Vec::new(),
        };
        let mut any = false;
        while let Some(message) = reader.next() {
            let message = message?;
            if let Message::Awareness(update) = message {
                if let Some(summary) = self
                    .awareness
                    .apply_update_summary(update)
                    .context("awareness_apply_update")?
                {
                    any = true;
                    combined.added.extend(summary.added);
                    combined.updated.extend(summary.updated);
                    combined.removed.extend(summary.removed);
                }
            }
        }
        if any {
            self.apply_summary(combined, origin).await;
        }
        Ok(())
    }

    pub async fn encode_full_state_frame(&self) -> anyhow::Result<Option<Vec<u8>>> {
        let update = self
            .awareness
            .update()
            .context("awareness_encode_full_state")?;
        if update.clients.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Message::Awareness(update).encode_v1()))
        }
    }

    pub fn spawn_ttl_task(&self) -> tokio::task::JoinHandle<()> {
        let manager = self.clone();
        tokio::spawn(async move {
            loop {
                let sleep_for = if manager.ttl.is_zero() {
                    Duration::from_secs(10)
                } else {
                    manager.ttl / 2
                };
                sleep(sleep_for).await;
                if let Err(err) = manager.prune_stale().await {
                    tracing::debug!(
                        document_id = %manager.doc_id,
                        error = ?err,
                        "awareness_prune_failed"
                    );
                }
            }
        })
    }

    async fn prune_stale(&self) -> anyhow::Result<()> {
        if self.ttl.is_zero() {
            return Ok(());
        }
        let now = Instant::now();
        let mut expired = Vec::new();
        {
            let mut guard = self.last_seen.lock().await;
            guard.retain(|client_id, instant| {
                if now.duration_since(*instant) > self.ttl {
                    expired.push(*client_id);
                    false
                } else {
                    true
                }
            });
        }
        if expired.is_empty() {
            return Ok(());
        }

        {
            let mut locals = self.local_clients.lock().await;
            for client in &expired {
                locals.remove(client);
            }
        }

        let entries = self.build_null_entries(&expired);
        for client in &expired {
            self.awareness.remove_state(*client);
        }
        if entries.is_empty() {
            return Ok(());
        }
        let update = AwarenessUpdate { clients: entries };
        let frame = Message::Awareness(update).encode_v1();
        self.publisher
            .publish_awareness(&self.doc_id, frame)
            .await
            .context("awareness_publish_removal")?;
        Ok(())
    }

    async fn apply_summary(&self, summary: AwarenessUpdateSummary, origin: FrameOrigin) {
        let now = Instant::now();
        let added: HashSet<ClientID> = summary.added.into_iter().collect();
        let updated: HashSet<ClientID> = summary.updated.into_iter().collect();
        let removed: HashSet<ClientID> = summary.removed.into_iter().collect();

        {
            let mut guard = self.last_seen.lock().await;
            for client in added.iter().chain(updated.iter()) {
                guard.insert(*client, now);
            }
            for client in &removed {
                guard.remove(client);
            }
        }

        if matches!(origin, FrameOrigin::Local) {
            let mut locals = self.local_clients.lock().await;
            for client in added.iter().chain(updated.iter()) {
                locals.insert(*client);
            }
            for client in &removed {
                locals.remove(client);
            }
        }
    }

    fn build_null_entries(&self, clients: &[ClientID]) -> HashMap<ClientID, AwarenessUpdateEntry> {
        let mut entries = HashMap::new();
        for client in clients {
            if let Some((clock, _)) = self.awareness.meta(*client) {
                entries.insert(
                    *client,
                    AwarenessUpdateEntry {
                        clock,
                        json: Arc::<str>::from("null"),
                    },
                );
            }
        }
        entries
    }
}

pub fn encode_awareness_state(awareness: &Awareness) -> anyhow::Result<Option<Vec<u8>>> {
    let update = awareness.update().context("awareness_encode")?;
    if update.clients.is_empty() {
        Ok(None)
    } else {
        Ok(Some(Message::Awareness(update).encode_v1()))
    }
}

#[derive(Clone, Copy)]
enum FrameOrigin {
    Local,
    Remote,
}
