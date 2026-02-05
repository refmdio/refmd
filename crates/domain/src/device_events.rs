//! Device event domain types
//!
//! Defines device-related events for SSE notifications.

use serde::{Deserialize, Serialize};

/// Device-related events for SSE
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    PendingRemoved { pending_id: String, user_id: String },
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
