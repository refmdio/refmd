use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::sync::Mutex;
use tokio::time::sleep;
use yrs::Doc;
use yrs::block::ClientID;
use yrs::encoding::read::Cursor;
use yrs::sync::awareness::{Awareness, AwarenessUpdate, AwarenessUpdateEntry};
use yrs::sync::{Message, MessageReader};
use yrs::updates::decoder::DecoderV1;
use yrs::updates::encoder::Encode;

use super::cluster_bus::RedisClusterBus;

#[derive(Clone)]
pub struct RedisAwarenessManager {
    awareness: Arc<Awareness>,
    last_seen: Arc<Mutex<HashMap<ClientID, Instant>>>,
    ttl: Duration,
    bus: Arc<RedisClusterBus>,
    doc_id: String,
}

impl RedisAwarenessManager {
    pub fn new(doc: Doc, bus: Arc<RedisClusterBus>, doc_id: String, ttl: Duration) -> Self {
        Self {
            awareness: Arc::new(Awareness::new(doc)),
            last_seen: Arc::new(Mutex::new(HashMap::new())),
            ttl,
            bus,
            doc_id,
        }
    }

    pub fn awareness(&self) -> Arc<Awareness> {
        self.awareness.clone()
    }

    pub async fn apply_remote_frame(&self, frame: &[u8]) -> anyhow::Result<()> {
        self.process_frame(frame).await
    }

    pub async fn record_local_frame(&self, frame: &[u8]) -> anyhow::Result<()> {
        self.process_frame(frame).await
    }

    async fn process_frame(&self, frame: &[u8]) -> anyhow::Result<()> {
        let mut decoder = DecoderV1::new(Cursor::new(frame));
        let mut reader = MessageReader::new(&mut decoder);
        while let Some(message) = reader.next() {
            let message = message?;
            if let Message::Awareness(update) = message {
                if let Some(summary) = self
                    .awareness
                    .apply_update_summary(update)
                    .context("apply_awareness_update")?
                {
                    let now = Instant::now();
                    if !summary.added.is_empty() || !summary.updated.is_empty() {
                        let mut guard = self.last_seen.lock().await;
                        for client_id in summary.added.iter().chain(summary.updated.iter()) {
                            guard.insert(*client_id, now);
                        }
                    }
                    if !summary.removed.is_empty() {
                        let mut guard = self.last_seen.lock().await;
                        for client_id in &summary.removed {
                            guard.remove(client_id);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn encode_full_state_frame(&self) -> anyhow::Result<Option<Vec<u8>>> {
        let update = self
            .awareness
            .update()
            .context("awareness_encode_full_state")?;
        if update.clients.is_empty() {
            return Ok(None);
        }
        Ok(Some(Message::Awareness(update).encode_v1()))
    }

    pub fn spawn_ttl_task(&self) -> tokio::task::JoinHandle<()> {
        let manager = self.clone();
        tokio::spawn(async move {
            loop {
                let sleep_dur = if manager.ttl.is_zero() {
                    Duration::from_secs(10)
                } else {
                    manager.ttl / 2
                };
                sleep(sleep_dur).await;
                if let Err(err) = manager.prune_stale().await {
                    tracing::debug!(
                        document_id = %manager.doc_id,
                        error = ?err,
                        "redis_awareness_prune_failed"
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

        for client in &expired {
            self.awareness.remove_state(*client);
        }
        let mut clients_map: HashMap<ClientID, AwarenessUpdateEntry> = HashMap::new();
        for client in expired {
            if let Some((clock, _)) = self.awareness.meta(client) {
                clients_map.insert(
                    client,
                    AwarenessUpdateEntry {
                        clock,
                        json: Arc::<str>::from("null"),
                    },
                );
            }
        }
        if clients_map.is_empty() {
            return Ok(());
        }
        let update = AwarenessUpdate {
            clients: clients_map,
        };
        let frame = Message::Awareness(update).encode_v1();
        self.bus
            .publish_awareness(&self.doc_id, frame)
            .await
            .context("redis_awareness_publish_removal")?;
        Ok(())
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
