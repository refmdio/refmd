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
    pub role_id: RoleId,
    pub invited_by: UserId,
    pub invited_email: Option<String>,
    pub max_uses: Option<i32>,
    pub use_count: i32,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl WorkspaceInvitation {
    /// Create a new invitation
    pub fn new(
        workspace_id: WorkspaceId,
        token_hash: String,
        token_prefix: String,
        role_id: RoleId,
        invited_by: UserId,
    ) -> Self {
        Self {
            id: InvitationId::new(),
            workspace_id,
            token_hash,
            token_prefix,
            role_id,
            invited_by,
            invited_email: None,
            max_uses: None,
            use_count: 0,
            expires_at: None,
            created_at: Utc::now(),
        }
    }

    /// Create an email-specific invitation
    pub fn for_email(
        workspace_id: WorkspaceId,
        token_hash: String,
        token_prefix: String,
        role_id: RoleId,
        invited_by: UserId,
        email: String,
    ) -> Self {
        let mut invitation = Self::new(workspace_id, token_hash, token_prefix, role_id, invited_by);
        invitation.invited_email = Some(email);
        invitation.max_uses = Some(1);
        invitation
    }

    /// Create a link invitation with optional limits
    pub fn link(
        workspace_id: WorkspaceId,
        token_hash: String,
        token_prefix: String,
        role_id: RoleId,
        invited_by: UserId,
        max_uses: Option<i32>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        let mut invitation = Self::new(workspace_id, token_hash, token_prefix, role_id, invited_by);
        invitation.max_uses = max_uses;
        invitation.expires_at = expires_at;
        invitation
    }

    /// Check if invitation is still valid
    pub fn is_valid(&self) -> bool {
        // Check expiration
        if let Some(expires_at) = self.expires_at
            && Utc::now() > expires_at
        {
            return false;
        }

        // Check max uses
        if let Some(max_uses) = self.max_uses
            && self.use_count >= max_uses
        {
            return false;
        }

        true
    }

    /// Check if invitation is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            return Utc::now() > expires_at;
        }
        false
    }

    /// Check if invitation has reached max uses
    pub fn is_exhausted(&self) -> bool {
        if let Some(max_uses) = self.max_uses {
            return self.use_count >= max_uses;
        }
        false
    }

    /// Increment use count
    pub fn use_invitation(&mut self) {
        self.use_count += 1;
    }

    /// Get remaining uses (None if unlimited)
    pub fn remaining_uses(&self) -> Option<i32> {
        self.max_uses.map(|max| max - self.use_count)
    }
}
