//! User entity

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::value_objects::Email;

/// User entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub email: Email,
    pub name: String,
    pub encryption_setup_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

define_id!(/// User ID value object
pub UserId);

impl User {
    /// Create a new user with server-generated ID
    pub fn new(email: Email, name: String) -> Self {
        let now = Utc::now();
        Self {
            id: UserId::new(),
            email,
            name,
            encryption_setup_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a new user with client-provided ID
    ///
    /// Used for AAD binding where client generates ID before encryption
    pub fn with_id(id: Uuid, email: Email, name: String) -> Self {
        let now = Utc::now();
        Self {
            id: UserId::from_uuid(id),
            email,
            name,
            encryption_setup_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Mark encryption as setup
    pub fn mark_encryption_setup(&mut self) {
        self.encryption_setup_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Check if encryption is setup
    pub fn is_encryption_setup(&self) -> bool {
        self.encryption_setup_at.is_some()
    }

    /// Update user name
    pub fn update_name(&mut self, name: String) {
        self.name = name;
        self.updated_at = Utc::now();
    }
}
