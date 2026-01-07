//! E2EE key types for workspaces

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Workspace encrypted key (KEK encrypted with user's public key)
#[derive(Debug, Clone)]
pub struct WorkspaceEncryptedKey {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub user_id: Uuid,
    pub encrypted_kek: Vec<u8>,
    pub key_version: i32,
    pub created_at: DateTime<Utc>,
}
