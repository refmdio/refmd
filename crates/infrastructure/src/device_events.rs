//! Redis Pub/Sub device event bus for HA mode
//!
//! Implements cross-instance event delivery for cluster deployments.

use application::dto::DeviceEventDto;
use application::events::{DeviceEventPublisher, DeviceEventSubscriber};
use async_trait::async_trait;
use domain::DeviceEvent;
use futures::StreamExt;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::RedisPool;

/// Redis channel name for device events
const REDIS_DEVICE_EVENTS_CHANNEL: &str = "device_events";

/// Redis message wrapper with origin instance ID to prevent self-delivery
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RedisEventMessage {
    /// Unique instance ID to identify the origin
    instance_id: String,
    /// The actual event payload
    event: DeviceEventDto,
}

/// Redis Pub/Sub event bus for cluster deployments
///
/// Publishes events to Redis and subscribes to receive events from other instances.
/// Uses a local broadcast channel for distribution to local SSE streams.
pub struct RedisDeviceEventBus {
    redis: RedisPool,
    redis_url: String,
    local_sender: broadcast::Sender<DeviceEvent>,
    /// Unique identifier for this instance (to avoid self-delivery from Redis)
    instance_id: String,
}

impl Clone for RedisDeviceEventBus {
    fn clone(&self) -> Self {
        Self {
            redis: self.redis.clone(),
            redis_url: self.redis_url.clone(),
            local_sender: self.local_sender.clone(),
            instance_id: self.instance_id.clone(),
        }
    }
}

impl RedisDeviceEventBus {
    /// Create a new Redis event bus and start the subscription listener
    pub fn new(redis: RedisPool, redis_url: String) -> Arc<Self> {
        let (local_sender, _) = broadcast::channel(256);
        // Use CLUSTER_BACKEND_ID if set, otherwise generate unique instance ID
        let instance_id = std::env::var("CLUSTER_BACKEND_ID")
            .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());

        tracing::info!("RedisDeviceEventBus instance_id: {}", instance_id);

        let bus = Arc::new(Self {
            redis: redis.clone(),
            redis_url,
            local_sender,
            instance_id,
        });

        // Start background subscription task
        let bus_clone = Arc::clone(&bus);
        tokio::spawn(async move {
            bus_clone.subscription_loop().await;
        });

        bus
    }

    /// Publish an event (local first, then Redis as best-effort)
    pub async fn publish(&self, event: DeviceEvent) {
        // Always deliver to local subscribers first (ensures delivery even if Redis is down)
        let _ = self.local_sender.send(event.clone());

        // Convert to wire-format payload
        let dto = DeviceEventDto::from(event);

        // Wrap event with instance_id for cross-instance deduplication
        let message = RedisEventMessage {
            instance_id: self.instance_id.clone(),
            event: dto,
        };

        // Then publish to Redis for cross-instance delivery (best-effort)
        let payload = match serde_json::to_string(&message) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Failed to serialize device event: {}", e);
                return;
            }
        };

        let mut conn = self.redis.connection();
        let result: Result<i32, _> = conn.publish(REDIS_DEVICE_EVENTS_CHANNEL, &payload).await;
        if let Err(e) = result {
            tracing::warn!(
                "Failed to publish device event to Redis (local delivery succeeded): {}",
                e
            );
        }
    }

    /// Subscribe to local events
    pub fn subscribe(&self) -> broadcast::Receiver<DeviceEvent> {
        self.local_sender.subscribe()
    }

    /// Background task that subscribes to Redis and forwards events locally
    async fn subscription_loop(self: &Arc<Self>) {
        loop {
            if let Err(e) = self.run_subscription().await {
                tracing::error!("Redis subscription error: {}. Reconnecting...", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }

    async fn run_subscription(&self) -> Result<(), redis::RedisError> {
        let client = redis::Client::open(self.redis_url.as_str())?;
        let mut pubsub = client.get_async_pubsub().await?;

        pubsub.subscribe(REDIS_DEVICE_EVENTS_CHANNEL).await?;
        tracing::info!(
            "Subscribed to Redis channel: {}",
            REDIS_DEVICE_EVENTS_CHANNEL
        );

        let mut stream = pubsub.on_message();
        while let Some(msg) = stream.next().await {
            let payload: String = msg.get_payload()?;
            match serde_json::from_str::<RedisEventMessage>(&payload) {
                Ok(message) => {
                    // Skip events from self (already delivered locally)
                    if message.instance_id == self.instance_id {
                        continue;
                    }
                    // Convert the Redis wire-format DTO back to a domain DeviceEvent
                    match DeviceEvent::try_from(message.event) {
                        Ok(event) => {
                            let _ = self.local_sender.send(event);
                        }
                        Err(e) => {
                            tracing::warn!("{}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to parse device event from Redis: {}", e);
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl DeviceEventPublisher for RedisDeviceEventBus {
    async fn publish(&self, event: DeviceEvent) {
        RedisDeviceEventBus::publish(self, event).await
    }
}

impl DeviceEventSubscriber for RedisDeviceEventBus {
    fn subscribe(&self) -> broadcast::Receiver<DeviceEvent> {
        RedisDeviceEventBus::subscribe(self)
    }
}
