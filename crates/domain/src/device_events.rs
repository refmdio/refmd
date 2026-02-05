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
    /// A pending device was removed (rejected)
    PendingRemoved { pending_id: String, user_id: String },
    /// A pending device expired
    PendingExpired { pending_id: String, user_id: String },
    /// New device requested trust transfer nonce
    TrustTransferNonceReady {
        user_id: String,
        /// The new device that requested the nonce
        new_device_id: String,
        /// Transfer nonce (base64url encoded, 32 bytes)
        nonce: String,
    },
}

impl DeviceEvent {
    /// Get the user ID this event belongs to
    pub fn user_id(&self) -> &str {
        match self {
            DeviceEvent::PendingCreated { user_id, .. } => user_id,
            DeviceEvent::PendingApproved { user_id, .. } => user_id,
            DeviceEvent::PendingRemoved { user_id, .. } => user_id,
            DeviceEvent::PendingExpired { user_id, .. } => user_id,
            DeviceEvent::TrustTransferNonceReady { user_id, .. } => user_id,
        }
    }

    /// Get the pending device ID this event relates to
    /// Returns empty string for events that don't have a pending_id
    pub fn pending_id(&self) -> &str {
        match self {
            DeviceEvent::PendingCreated { pending_id, .. } => pending_id,
            DeviceEvent::PendingApproved { pending_id, .. } => pending_id,
            DeviceEvent::PendingRemoved { pending_id, .. } => pending_id,
            DeviceEvent::PendingExpired { pending_id, .. } => pending_id,
            DeviceEvent::TrustTransferNonceReady { .. } => "",
        }
    }
}
