//! Workspace invitation entity

use chrono::{DateTime, Utc};

use super::value_objects::{InvitationId, RoleId, WorkspaceId};
use crate::identity::UserId;

/// Workspace invitation
#[derive(Debug, Clone)]
pub struct WorkspaceInvitation {
    pub id: InvitationId,
    pub workspace_id: WorkspaceId,
    pub token_hash: String,
    pub token_prefix: String,
    pub role_id: Option<RoleId>,
    pub invited_by: UserId,
    pub invited_email: String,
    pub encrypted_kek: Vec<u8>,
    pub kek_nonce: Vec<u8>,
    pub kek_version: i32,
    pub is_used: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Parameters for creating a new workspace invitation
pub struct NewInvitationParams {
    pub id: InvitationId,
    pub workspace_id: WorkspaceId,
    pub token_hash: String,
    pub token_prefix: String,
    pub role_id: RoleId,
    pub invited_by: UserId,
    pub invited_email: String,
    pub encrypted_kek: Vec<u8>,
    pub kek_nonce: Vec<u8>,
    pub kek_version: i32,
    pub expires_at: DateTime<Utc>,
}

impl WorkspaceInvitation {
    /// Create a new invitation
    pub fn new(params: NewInvitationParams) -> Self {
        Self {
            id: params.id,
            workspace_id: params.workspace_id,
            token_hash: params.token_hash,
            token_prefix: params.token_prefix,
            role_id: Some(params.role_id),
            invited_by: params.invited_by,
            invited_email: params.invited_email,
            encrypted_kek: params.encrypted_kek,
            kek_nonce: params.kek_nonce,
            kek_version: params.kek_version,
            is_used: false,
            revoked_at: None,
            expires_at: params.expires_at,
            created_at: Utc::now(),
        }
    }

}
