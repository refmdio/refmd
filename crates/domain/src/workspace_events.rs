//! Workspace event domain types
//!
//! Defines workspace-related events for SSE notifications.
//! Domain events use strong types; serialization is handled by
//! `WorkspaceEventDto` in the application layer.

use crate::identity::UserId;
use crate::workspace::{InvitationId, WorkspaceId};

/// Workspace-related events (strong-typed domain model)
#[derive(Debug, Clone)]
pub enum WorkspaceEvent {
    /// An invitation was accepted and a new member joined the workspace
    InvitationAccepted {
        workspace_id: WorkspaceId,
        invitation_id: InvitationId,
        accepted_by_email: String,
        /// User IDs of existing workspace members (for SSE filtering)
        member_user_ids: Vec<UserId>,
    },
    /// A member was removed from the workspace
    MemberRemoved {
        workspace_id: WorkspaceId,
        removed_user_id: UserId,
    },
    /// A member's role was changed in the workspace
    MemberRoleChanged {
        workspace_id: WorkspaceId,
        target_user_id: UserId,
    },
}

impl WorkspaceEvent {
    /// Check if this event is relevant for a specific user.
    ///
    /// Fail-closed: empty `member_user_ids` suppresses delivery rather than
    /// broadcasting to all users (prevents information leakage).
    pub fn is_for_user(&self, user_id: UserId) -> bool {
        match self {
            WorkspaceEvent::InvitationAccepted {
                member_user_ids, ..
            } => member_user_ids.contains(&user_id),
            WorkspaceEvent::MemberRemoved {
                removed_user_id, ..
            } => *removed_user_id == user_id,
            WorkspaceEvent::MemberRoleChanged {
                target_user_id, ..
            } => *target_user_id == user_id,
        }
    }
}
