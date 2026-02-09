//! Session entity

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

/// Session ID value object
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Session duration constants
const SESSION_DURATION_HOURS: i64 = 24;
const REMEMBER_ME_DURATION_DAYS: i64 = 30;

impl Session {
    /// Create a new session
    pub fn new(
        user_id: UserId,
        token_hash: String,
        remember_me: bool,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Self {
        Self::with_device(
            user_id,
            None,
            token_hash,
            remember_me,
            ip_address,
            user_agent,
        )
    }

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

    /// Check if the session is valid
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }

    /// Extend session expiration
    pub fn extend(&mut self) {
        let duration = if self.remember_me {
            Duration::days(REMEMBER_ME_DURATION_DAYS)
        } else {
            Duration::hours(SESSION_DURATION_HOURS)
        };
        self.expires_at = Utc::now() + duration;
    }
}
