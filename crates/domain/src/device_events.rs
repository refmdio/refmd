//! Device event domain types
//!
//! Defines device-related events for SSE notifications.
//! Domain events use strong types; serialization is handled by
//! `DeviceEventDto` in the application layer.

use crate::encryption::{DeviceId, DeviceType};
use crate::identity::UserId;

/// Device-related events (strong-typed domain model)
#[derive(Debug, Clone)]
pub enum DeviceEvent {
    /// A new pending device was created
    PendingCreated {
        pending_id: DeviceId,
        user_id: UserId,
        device_name: String,
        device_type: DeviceType,
        ip_address: Option<String>,
        expires_at: chrono::DateTime<chrono::Utc>,
    },
    /// A pending device was approved
    PendingApproved {
        pending_id: DeviceId,
        user_id: UserId,
        device_id: DeviceId,
    },
    /// A pending device was removed (rejected)
    PendingRemoved {
        pending_id: DeviceId,
        user_id: UserId,
    },
    /// A pending device expired
    PendingExpired {
        pending_id: DeviceId,
        user_id: UserId,
    },
    /// New device requested trust transfer nonce
    TrustTransferNonceReady {
        user_id: UserId,
        /// The new device that requested the nonce
        new_device_id: DeviceId,
        /// Transfer nonce (raw bytes, 32 bytes)
        nonce: Vec<u8>,
    },
}

impl DeviceEvent {
    /// Get the user ID this event belongs to
    pub fn user_id(&self) -> UserId {
        match self {
            DeviceEvent::PendingCreated { user_id, .. } => *user_id,
            DeviceEvent::PendingApproved { user_id, .. } => *user_id,
            DeviceEvent::PendingRemoved { user_id, .. } => *user_id,
            DeviceEvent::PendingExpired { user_id, .. } => *user_id,
            DeviceEvent::TrustTransferNonceReady { user_id, .. } => *user_id,
        }
    }

    /// Get the pending device ID this event relates to (if applicable)
    pub fn pending_id(&self) -> Option<DeviceId> {
        match self {
            DeviceEvent::PendingCreated { pending_id, .. } => Some(*pending_id),
            DeviceEvent::PendingApproved { pending_id, .. } => Some(*pending_id),
            DeviceEvent::PendingRemoved { pending_id, .. } => Some(*pending_id),
            DeviceEvent::PendingExpired { pending_id, .. } => Some(*pending_id),
            DeviceEvent::TrustTransferNonceReady { .. } => None,
        }
    }
}
