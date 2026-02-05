//! Device event bus for SSE notifications
//!
//! Provides real-time notifications for device registration events.

use application::domain::encryption::DeviceId;
use application::domain::identity::UserId;
use async_trait::async_trait;
use tokio::sync::broadcast;

// Re-export from domain
pub use application::domain::DeviceEvent;

/// Trait for publishing device events
#[async_trait]
pub trait DeviceEventPublisher: Send + Sync {
    /// Publish an event
    async fn publish(&self, event: DeviceEvent);

    /// Publish a pending device created event
    async fn pending_created(
        &self,
        pending_id: DeviceId,
        user_id: UserId,
        device_name: String,
        device_type: String,
        ip_address: Option<String>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) {
        self.publish(DeviceEvent::PendingCreated {
            pending_id: pending_id.to_string(),
            user_id: user_id.to_string(),
            device_name,
            device_type,
            ip_address,
            expires_at: expires_at.to_rfc3339(),
        })
        .await;
    }

    /// Publish a pending device approved event
    async fn pending_approved(&self, pending_id: DeviceId, user_id: UserId, device_id: DeviceId) {
        self.publish(DeviceEvent::PendingApproved {
            pending_id: pending_id.to_string(),
            user_id: user_id.to_string(),
            device_id: device_id.to_string(),
        })
        .await;
    }

    /// Publish a pending device removed event
    async fn pending_removed(&self, pending_id: DeviceId, user_id: UserId) {
        self.publish(DeviceEvent::PendingRemoved {
            pending_id: pending_id.to_string(),
            user_id: user_id.to_string(),
        })
        .await;
    }

    /// Publish a pending device expired event
    async fn pending_expired(&self, pending_id: DeviceId, user_id: UserId) {
        self.publish(DeviceEvent::PendingExpired {
            pending_id: pending_id.to_string(),
            user_id: user_id.to_string(),
        })
        .await;
    }

    /// Publish a trust transfer nonce ready event
    async fn trust_transfer_nonce_ready(
        &self,
        user_id: UserId,
        new_device_id: DeviceId,
        nonce: &[u8],
    ) {
        self.publish(DeviceEvent::TrustTransferNonceReady {
            user_id: user_id.to_string(),
            new_device_id: new_device_id.to_string(),
            nonce: base64_url::encode(nonce),
        })
        .await;
    }
}

/// Trait for subscribing to device events
pub trait DeviceEventSubscriber: Send + Sync {
    /// Subscribe to events
    fn subscribe(&self) -> broadcast::Receiver<DeviceEvent>;
}

/// Combined trait for convenience
pub trait DeviceEventBus: DeviceEventPublisher + DeviceEventSubscriber {}

impl<T: DeviceEventPublisher + DeviceEventSubscriber> DeviceEventBus for T {}

/// In-memory event bus for single-node deployments
#[derive(Clone)]
pub struct InMemoryDeviceEventBus {
    sender: broadcast::Sender<DeviceEvent>,
}

impl Default for InMemoryDeviceEventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryDeviceEventBus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(256);
        Self { sender }
    }
}

#[async_trait]
impl DeviceEventPublisher for InMemoryDeviceEventBus {
    async fn publish(&self, event: DeviceEvent) {
        let _ = self.sender.send(event);
    }
}

impl DeviceEventSubscriber for InMemoryDeviceEventBus {
    fn subscribe(&self) -> broadcast::Receiver<DeviceEvent> {
        self.sender.subscribe()
    }
}
