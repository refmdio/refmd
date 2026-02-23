use chrono::{DateTime, Utc};

use domain::identity::UserId;
use domain::workspace::{
    InvitationId, RoleId, Workspace, WorkspaceId, WorkspaceInvitation, WorkspaceMember,
    WorkspaceRole,
};

/// DTO for Workspace entity
#[derive(Debug, Clone)]
pub struct WorkspaceDto {
    pub id: WorkspaceId,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub owner_id: UserId,
    pub min_kek_version: i32,
    pub needs_kek_rotation: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Workspace> for WorkspaceDto {
    fn from(w: Workspace) -> Self {
        Self {
            id: w.id,
            name: w.name,
            slug: w.slug.to_string(),
            description: w.description,
            icon: w.icon,
            owner_id: w.owner_id,
            min_kek_version: w.min_kek_version,
            needs_kek_rotation: w.needs_kek_rotation,
            created_at: w.created_at,
            updated_at: w.updated_at,
        }
    }
}

/// DTO for WorkspaceMember entity
#[derive(Debug, Clone)]
pub struct WorkspaceMemberDto {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub role_id: RoleId,
    pub is_default: bool,
    pub joined_at: DateTime<Utc>,
}

impl From<WorkspaceMember> for WorkspaceMemberDto {
    fn from(m: WorkspaceMember) -> Self {
        Self {
            workspace_id: m.workspace_id,
            user_id: m.user_id,
            role_id: m.role_id,
            is_default: m.is_default,
            joined_at: m.joined_at,
        }
    }
}

/// DTO for WorkspaceRole entity
#[derive(Debug, Clone)]
pub struct WorkspaceRoleDto {
    pub id: RoleId,
    pub workspace_id: WorkspaceId,
    pub name: String,
    pub base_role: String,
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
    /// Permission overrides from the DB (empty if none)
    pub permission_overrides: Vec<(String, bool)>,
}

impl From<WorkspaceRole> for WorkspaceRoleDto {
    fn from(r: WorkspaceRole) -> Self {
        Self {
            id: r.id,
            workspace_id: r.workspace_id,
            name: r.name,
            base_role: r.base_role.to_string(),
            is_default: r.is_default,
            created_at: r.created_at,
            permission_overrides: Vec::new(),
        }
    }
}

/// DTO for WorkspaceInvitation entity
#[derive(Debug, Clone)]
pub struct WorkspaceInvitationDto {
    pub id: InvitationId,
    pub workspace_id: WorkspaceId,
    pub token_prefix: String,
    pub role_id: Option<RoleId>,
    pub invited_by: UserId,
    pub invited_email: String,
    pub kek_version: i32,
    pub is_used: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl From<WorkspaceInvitation> for WorkspaceInvitationDto {
    fn from(i: WorkspaceInvitation) -> Self {
        Self {
            id: i.id,
            workspace_id: i.workspace_id,
            token_prefix: i.token_prefix,
            role_id: i.role_id,
            invited_by: i.invited_by,
            invited_email: i.invited_email,
            kek_version: i.kek_version,
            is_used: i.is_used,
            revoked_at: i.revoked_at,
            expires_at: i.expires_at,
            created_at: i.created_at,
        }
    }
}
