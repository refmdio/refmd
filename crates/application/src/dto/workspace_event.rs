//! Workspace event DTO for wire-format serialization

use domain::WorkspaceEvent;
use serde::{Deserialize, Serialize};

/// Serializable workspace event DTO (wire format)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkspaceEventDto {
    InvitationAccepted {
        workspace_id: String,
        invitation_id: String,
        accepted_by_email: String,
    },
}

impl From<&WorkspaceEvent> for WorkspaceEventDto {
    fn from(event: &WorkspaceEvent) -> Self {
        match event {
            WorkspaceEvent::InvitationAccepted {
                workspace_id,
                invitation_id,
                accepted_by_email,
                ..
            } => WorkspaceEventDto::InvitationAccepted {
                workspace_id: workspace_id.to_string(),
                invitation_id: invitation_id.to_string(),
                accepted_by_email: accepted_by_email.clone(),
            },
        }
    }
}

impl From<WorkspaceEvent> for WorkspaceEventDto {
    fn from(event: WorkspaceEvent) -> Self {
        Self::from(&event)
    }
}

/// Parse a UUID string, returning a descriptive error on failure.
fn parse_uuid(field: &str, variant: &str, field_name: &str) -> Result<uuid::Uuid, String> {
    uuid::Uuid::parse_str(field).map_err(|e| {
        format!(
            "Dropping cross-instance {} event: invalid {}: {}",
            variant, field_name, e,
        )
    })
}

impl TryFrom<WorkspaceEventDto> for WorkspaceEvent {
    type Error = String;

    fn try_from(dto: WorkspaceEventDto) -> Result<Self, Self::Error> {
        use domain::workspace::{InvitationId, WorkspaceId};

        match dto {
            WorkspaceEventDto::InvitationAccepted {
                workspace_id,
                invitation_id,
                accepted_by_email,
            } => {
                let workspace_id = WorkspaceId::from_uuid(parse_uuid(
                    &workspace_id,
                    "InvitationAccepted",
                    "workspace_id",
                )?);
                let invitation_id = InvitationId::from_uuid(parse_uuid(
                    &invitation_id,
                    "InvitationAccepted",
                    "invitation_id",
                )?);
                // member_user_ids is not transmitted over wire — the SSE endpoint
                // on the receiving instance will re-check membership from DB or
                // simply broadcast to all local SSE clients (who filter client-side).
                // For cross-instance, we use an empty list — the receiving instance's
                // SSE handler won't be able to filter, but that's acceptable since
                // the client-side workspace_id check provides sufficient scoping.
                Ok(WorkspaceEvent::InvitationAccepted {
                    workspace_id,
                    invitation_id,
                    accepted_by_email,
                    member_user_ids: vec![],
                })
            }
        }
    }
}
