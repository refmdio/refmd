//! Device event bus traits
//!
//! Defines the event publishing and subscribing contracts used by application-layer
//! handlers and presentation-layer SSE routes. Implementations live in the
//! infrastructure layer.

use async_trait::async_trait;
use domain::DeviceEvent;
use domain::encryption::{DeviceId, DeviceType};
use domain::identity::UserId;
use tokio::sync::broadcast;

/// Trait for publishing device events from the application layer.
///
/// Handlers inject `Arc<dyn DeviceEventPublisher>` to fire events
/// after successful operations, keeping event logic inside use cases
/// rather than scattering it across HTTP routes.
#[async_trait]
pub trait DeviceEventPublisher: Send + Sync {
    /// Publish a device event.
    async fn publish(&self, event: DeviceEvent);

    /// Publish a pending device created event.
    async fn pending_created(
        &self,
        pending_id: DeviceId,
        user_id: UserId,
        device_name: String,
        device_type: DeviceType,
        ip_address: Option<String>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) {
        self.publish(DeviceEvent::PendingCreated {
            pending_id,
            user_id,
            device_name,
            device_type,
            ip_address,
            expires_at,
        })
        .await;
    }

    /// Publish a pending device approved event.
    async fn pending_approved(&self, pending_id: DeviceId, user_id: UserId, device_id: DeviceId) {
        self.publish(DeviceEvent::PendingApproved {
            pending_id,
            user_id,
            device_id,
        })
        .await;
    }

    /// Publish a pending device removed event.
    async fn pending_removed(&self, pending_id: DeviceId, user_id: UserId) {
        self.publish(DeviceEvent::PendingRemoved {
            pending_id,
            user_id,
        })
        .await;
    }

    /// Publish a pending device expired event.
    async fn pending_expired(&self, pending_id: DeviceId, user_id: UserId) {
        self.publish(DeviceEvent::PendingExpired {
            pending_id,
            user_id,
        })
        .await;
    }

    /// Publish a trust transfer nonce ready event.
    async fn trust_transfer_nonce_ready(
        &self,
        user_id: UserId,
        new_device_id: DeviceId,
        nonce: &[u8],
    ) {
        self.publish(DeviceEvent::TrustTransferNonceReady {
            user_id,
            new_device_id,
            nonce: nonce.to_vec(),
        })
        .await;
    }
}

/// Trait for subscribing to device events (used by SSE routes).
pub trait DeviceEventSubscriber: Send + Sync {
    /// Subscribe to events.
    fn subscribe(&self) -> broadcast::Receiver<DeviceEvent>;
}

/// Combined publish + subscribe trait for convenience.
pub trait DeviceEventBus: DeviceEventPublisher + DeviceEventSubscriber {}

impl<T: DeviceEventPublisher + DeviceEventSubscriber> DeviceEventBus for T {}
