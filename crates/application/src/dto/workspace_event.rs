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
        member_user_ids: Vec<String>,
    },
    MemberRemoved {
        workspace_id: String,
        removed_user_id: String,
    },
    MemberRoleChanged {
        workspace_id: String,
        target_user_id: String,
    },
}

impl From<&WorkspaceEvent> for WorkspaceEventDto {
    fn from(event: &WorkspaceEvent) -> Self {
        match event {
            WorkspaceEvent::InvitationAccepted {
                workspace_id,
                invitation_id,
                accepted_by_email,
                member_user_ids,
            } => WorkspaceEventDto::InvitationAccepted {
                workspace_id: workspace_id.to_string(),
                invitation_id: invitation_id.to_string(),
                accepted_by_email: accepted_by_email.clone(),
                member_user_ids: member_user_ids.iter().map(|id| id.to_string()).collect(),
            },
            WorkspaceEvent::MemberRemoved {
                workspace_id,
                removed_user_id,
            } => WorkspaceEventDto::MemberRemoved {
                workspace_id: workspace_id.to_string(),
                removed_user_id: removed_user_id.to_string(),
            },
            WorkspaceEvent::MemberRoleChanged {
                workspace_id,
                target_user_id,
            } => WorkspaceEventDto::MemberRoleChanged {
                workspace_id: workspace_id.to_string(),
                target_user_id: target_user_id.to_string(),
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
        use domain::identity::UserId;
        use domain::workspace::{InvitationId, WorkspaceId};

        match dto {
            WorkspaceEventDto::InvitationAccepted {
                workspace_id,
                invitation_id,
                accepted_by_email,
                member_user_ids,
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
                let member_user_ids = member_user_ids
                    .into_iter()
                    .map(|id| {
                        parse_uuid(&id, "InvitationAccepted", "member_user_ids[]")
                            .map(UserId::from_uuid)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(WorkspaceEvent::InvitationAccepted {
                    workspace_id,
                    invitation_id,
                    accepted_by_email,
                    member_user_ids,
                })
            }
            WorkspaceEventDto::MemberRemoved {
                workspace_id,
                removed_user_id,
            } => {
                let workspace_id = WorkspaceId::from_uuid(parse_uuid(
                    &workspace_id,
                    "MemberRemoved",
                    "workspace_id",
                )?);
                let removed_user_id = UserId::from_uuid(parse_uuid(
                    &removed_user_id,
                    "MemberRemoved",
                    "removed_user_id",
                )?);
                Ok(WorkspaceEvent::MemberRemoved {
                    workspace_id,
                    removed_user_id,
                })
            }
            WorkspaceEventDto::MemberRoleChanged {
                workspace_id,
                target_user_id,
            } => {
                let workspace_id = WorkspaceId::from_uuid(parse_uuid(
                    &workspace_id,
                    "MemberRoleChanged",
                    "workspace_id",
                )?);
                let target_user_id = UserId::from_uuid(parse_uuid(
                    &target_user_id,
                    "MemberRoleChanged",
                    "target_user_id",
                )?);
                Ok(WorkspaceEvent::MemberRoleChanged {
                    workspace_id,
                    target_user_id,
                })
            }
        }
    }
}
