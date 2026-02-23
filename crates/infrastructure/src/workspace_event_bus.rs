//! Redis Pub/Sub workspace event bus for HA mode
//!
//! Implements cross-instance event delivery for cluster deployments.

use application::dto::WorkspaceEventDto;
use application::workspace_events::{WorkspaceEventPublisher, WorkspaceEventSubscriber};
use async_trait::async_trait;
use domain::WorkspaceEvent;
use futures::StreamExt;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::RedisPool;

/// Redis channel name for workspace events
const REDIS_WORKSPACE_EVENTS_CHANNEL: &str = "workspace_events";

/// Redis message wrapper with origin instance ID to prevent self-delivery
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RedisEventMessage {
    instance_id: String,
    event: WorkspaceEventDto,
}

/// Redis Pub/Sub event bus for cluster deployments
pub struct RedisWorkspaceEventBus {
    redis: RedisPool,
    redis_url: String,
    local_sender: broadcast::Sender<WorkspaceEvent>,
    instance_id: String,
}

impl Clone for RedisWorkspaceEventBus {
    fn clone(&self) -> Self {
        Self {
            redis: self.redis.clone(),
            redis_url: self.redis_url.clone(),
            local_sender: self.local_sender.clone(),
            instance_id: self.instance_id.clone(),
        }
    }
}

impl RedisWorkspaceEventBus {
    /// Create a new Redis event bus and start the subscription listener
    pub fn new(redis: RedisPool, redis_url: String) -> Arc<Self> {
        let (local_sender, _) = broadcast::channel(256);
        let instance_id = std::env::var("CLUSTER_BACKEND_ID")
            .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());

        tracing::info!("RedisWorkspaceEventBus instance_id: {}", instance_id);

        let bus = Arc::new(Self {
            redis: redis.clone(),
            redis_url,
            local_sender,
            instance_id,
        });

        let bus_clone = Arc::clone(&bus);
        tokio::spawn(async move {
            bus_clone.subscription_loop().await;
        });

        bus
    }

    /// Publish an event (local first, then Redis as best-effort)
    pub async fn publish(&self, event: WorkspaceEvent) {
        let _ = self.local_sender.send(event.clone());

        let dto = WorkspaceEventDto::from(event);
        let message = RedisEventMessage {
            instance_id: self.instance_id.clone(),
            event: dto,
        };

        let payload = match serde_json::to_string(&message) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Failed to serialize workspace event: {}", e);
                return;
            }
        };

        let mut conn = self.redis.connection();
        let result: Result<i32, _> = conn.publish(REDIS_WORKSPACE_EVENTS_CHANNEL, &payload).await;
        if let Err(e) = result {
            tracing::warn!(
                "Failed to publish workspace event to Redis (local delivery succeeded): {}",
                e
            );
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<WorkspaceEvent> {
        self.local_sender.subscribe()
    }

    async fn subscription_loop(self: &Arc<Self>) {
        loop {
            if let Err(e) = self.run_subscription().await {
                tracing::error!("Redis workspace subscription error: {}. Reconnecting...", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }

    async fn run_subscription(&self) -> Result<(), redis::RedisError> {
        let client = redis::Client::open(self.redis_url.as_str())?;
        let mut pubsub = client.get_async_pubsub().await?;

        pubsub.subscribe(REDIS_WORKSPACE_EVENTS_CHANNEL).await?;
        tracing::info!(
            "Subscribed to Redis channel: {}",
            REDIS_WORKSPACE_EVENTS_CHANNEL
        );

        let mut stream = pubsub.on_message();
        while let Some(msg) = stream.next().await {
            let payload: String = msg.get_payload()?;
            match serde_json::from_str::<RedisEventMessage>(&payload) {
                Ok(message) => {
                    if message.instance_id == self.instance_id {
                        continue;
                    }
                    match WorkspaceEvent::try_from(message.event) {
                        Ok(event) => {
                            let _ = self.local_sender.send(event);
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                source_instance = %message.instance_id,
                                "failed to convert workspace event DTO to domain event"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        channel = REDIS_WORKSPACE_EVENTS_CHANNEL,
                        "failed to deserialize workspace event from Redis"
                    );
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl WorkspaceEventPublisher for RedisWorkspaceEventBus {
    async fn publish(&self, event: WorkspaceEvent) {
        RedisWorkspaceEventBus::publish(self, event).await
    }
}

impl WorkspaceEventSubscriber for RedisWorkspaceEventBus {
    fn subscribe(&self) -> broadcast::Receiver<WorkspaceEvent> {
        RedisWorkspaceEventBus::subscribe(self)
    }
}
