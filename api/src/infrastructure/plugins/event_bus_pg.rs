use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use futures_util::stream::{BoxStream, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_stream::wrappers::UnboundedReceiverStream;

use crate::application::ports::plugin_event_publisher::{PluginEventPublisher, PluginScopedEvent};
use crate::infrastructure::db::PgPool;

#[derive(Clone)]
pub struct PgPluginEventBus {
    pool: PgPool,
    channel: String,
}

impl PgPluginEventBus {
    pub fn new(pool: PgPool, channel: impl Into<String>) -> Self {
        Self {
            pool,
            channel: channel.into(),
        }
    }

    pub async fn subscribe(&self) -> anyhow::Result<BoxStream<'static, PluginScopedEvent>> {
        let (tx, rx) = mpsc::unbounded_channel::<PluginScopedEvent>();
        let pool = self.pool.clone();
        let channel = self.channel.clone();

        tokio::spawn(async move {
            loop {
                let listener = sqlx::postgres::PgListener::connect_with(&pool)
                    .await
                    .context("plugin_event_listener_connect");
                let mut listener = match listener {
                    Ok(listener) => listener,
                    Err(err) => {
                        tracing::error!(error = ?err, "plugin_event_listener_connect_failed");
                        sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };

                if let Err(err) = listener.listen(&channel).await {
                    tracing::error!(error = ?err, channel = %channel, "plugin_event_listener_listen_failed");
                    sleep(Duration::from_secs(1)).await;
                    continue;
                }

                loop {
                    match listener.recv().await {
                        Ok(notification) => {
                            let payload = notification.payload();
                            match serde_json::from_str::<EventEnvelope>(payload) {
                                Ok(envelope) => {
                                    let event = PluginScopedEvent {
                                        user_id: envelope.user_id,
                                        payload: envelope.payload,
                                    };
                                    if tx.send(event).is_err() {
                                        return;
                                    }
                                }
                                Err(err) => {
                                    tracing::error!(
                                        error = ?err,
                                        raw_payload = payload,
                                        "plugin_event_listener_decode_failed"
                                    );
                                }
                            }
                        }
                        Err(err) => {
                            tracing::error!(error = ?err, channel = %channel, "plugin_event_listener_recv_failed");
                            sleep(Duration::from_millis(500)).await;
                            break;
                        }
                    }
                }
            }
        });

        let stream = UnboundedReceiverStream::new(rx).boxed();
        Ok(stream)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct EventEnvelope {
    user_id: Option<uuid::Uuid>,
    payload: serde_json::Value,
}

#[async_trait]
impl PluginEventPublisher for PgPluginEventBus {
    async fn publish(&self, event: &PluginScopedEvent) -> anyhow::Result<()> {
        let envelope = EventEnvelope {
            user_id: event.user_id,
            payload: event.payload.clone(),
        };
        let payload = serde_json::to_string(&envelope).context("plugin_event_serialize")?;

        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(&self.channel)
            .bind(payload)
            .execute(&self.pool)
            .await
            .context("plugin_event_pg_notify")?;

        Ok(())
    }
}
