//! Session entity

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::user::UserId;
use crate::encryption::DeviceId;

/// Session entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
    pub token_hash: String,
    pub remember_me: bool,
    pub is_recovery: bool,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

define_id!(/// Session ID value object
pub SessionId);

/// Session duration constants
const SESSION_DURATION_HOURS: i64 = 24;
const REMEMBER_ME_DURATION_DAYS: i64 = 30;

impl Session {
    /// Create a new recovery session (no device binding, is_recovery = true)
    pub fn new_recovery(
        user_id: UserId,
        token_hash: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Self {
        let now = Utc::now();
        let expires_at = now + Duration::hours(SESSION_DURATION_HOURS);

        Self {
            id: SessionId::new(),
            user_id,
            device_id: None,
            token_hash,
            remember_me: false,
            is_recovery: true,
            ip_address,
            user_agent,
            expires_at,
            created_at: now,
        }
    }

    /// Create a new session with a device ID
    pub fn with_device(
        user_id: UserId,
        device_id: Option<DeviceId>,
        token_hash: String,
        remember_me: bool,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Self {
        let now = Utc::now();
        let expires_at = if remember_me {
            now + Duration::days(REMEMBER_ME_DURATION_DAYS)
        } else {
            now + Duration::hours(SESSION_DURATION_HOURS)
        };

        Self {
            id: SessionId::new(),
            user_id,
            device_id,
            token_hash,
            remember_me,
            is_recovery: false,
            ip_address,
            user_agent,
            expires_at,
            created_at: now,
        }
    }

    /// Check if the session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Bind a device to this session
    pub fn bind_device(&mut self, device_id: DeviceId) {
        self.device_id = Some(device_id);
    }
}
