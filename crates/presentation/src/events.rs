//! Device event bus for SSE notifications
//!
//! Provides real-time notifications for device registration events.

use application::domain::encryption::DeviceId;
use application::domain::identity::UserId;
use serde::Serialize;
use tokio::sync::broadcast;

/// Device-related events for SSE
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeviceEvent {
    /// A new pending device was created
    PendingCreated {
        pending_id: String,
        user_id: String,
        device_name: String,
        device_type: String,
        ip_address: Option<String>,
        expires_at: String,
    },
    /// A pending device was approved
    PendingApproved {
        pending_id: String,
        user_id: String,
        device_id: String,
    },
    /// A pending device expired or was removed
    PendingRemoved {
        pending_id: String,
        user_id: String,
    },
}

impl DeviceEvent {
    /// Get the user ID this event belongs to
    pub fn user_id(&self) -> &str {
        match self {
            DeviceEvent::PendingCreated { user_id, .. } => user_id,
            DeviceEvent::PendingApproved { user_id, .. } => user_id,
            DeviceEvent::PendingRemoved { user_id, .. } => user_id,
        }
    }

    /// Get the pending device ID this event relates to
    pub fn pending_id(&self) -> &str {
        match self {
            DeviceEvent::PendingCreated { pending_id, .. } => pending_id,
            DeviceEvent::PendingApproved { pending_id, .. } => pending_id,
            DeviceEvent::PendingRemoved { pending_id, .. } => pending_id,
        }
    }
}

/// Event bus for device events
#[derive(Clone)]
pub struct DeviceEventBus {
    sender: broadcast::Sender<DeviceEvent>,
}

impl Default for DeviceEventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceEventBus {
    /// Create a new event bus with default capacity
    pub fn new() -> Self {
        // Capacity of 256 should be enough for most use cases
        let (sender, _) = broadcast::channel(256);
        Self { sender }
    }

    /// Publish an event to all subscribers
    pub fn publish(&self, event: DeviceEvent) {
        // Ignore send errors (no subscribers)
        let _ = self.sender.send(event);
    }

    /// Subscribe to events
    pub fn subscribe(&self) -> broadcast::Receiver<DeviceEvent> {
        self.sender.subscribe()
    }

    /// Publish a pending device created event
    pub fn pending_created(
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
        });
    }

    /// Publish a pending device approved event
    pub fn pending_approved(&self, pending_id: DeviceId, user_id: UserId, device_id: DeviceId) {
        self.publish(DeviceEvent::PendingApproved {
            pending_id: pending_id.to_string(),
            user_id: user_id.to_string(),
            device_id: device_id.to_string(),
        });
    }

    /// Publish a pending device removed event
    pub fn pending_removed(&self, pending_id: DeviceId, user_id: UserId) {
        self.publish(DeviceEvent::PendingRemoved {
            pending_id: pending_id.to_string(),
            user_id: user_id.to_string(),
        });
    }
}
