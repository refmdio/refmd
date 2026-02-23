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
}

impl WorkspaceEvent {
    /// Check if this event is relevant for a specific user.
    ///
    /// When `member_user_ids` is empty (cross-instance deserialization),
    /// broadcasts to all connected users — the frontend filters by workspace.
    pub fn is_for_user(&self, user_id: UserId) -> bool {
        match self {
            WorkspaceEvent::InvitationAccepted {
                member_user_ids, ..
            } => member_user_ids.is_empty() || member_user_ids.contains(&user_id),
        }
    }
}
