use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use domain::workspaces::permissions::{
    PermissionOverride, PermissionSet, apply_custom_overrides, system_role_permissions,
};
use domain::workspaces::roles::{WorkspaceBaseRole, WorkspaceRoleKind, WorkspaceSystemRole};

pub mod permission_snapshot;
mod slug;
use crate::core::services::errors::ServiceError;
use crate::workspaces::ports::workspace_repository::{
    WorkspaceInvitationRecord, WorkspaceListItem, WorkspaceMemberDetail, WorkspaceMemberRow,
    WorkspaceRepository, WorkspaceRoleRecord, WorkspaceRow, WorkspaceSetDefaultError,
};

#[async_trait]
pub trait WorkspacePermissionResolver: Send + Sync {
    async fn load_permission_set(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<PermissionSet>, ServiceError>;
}

pub struct WorkspaceService {
    repo: Arc<dyn WorkspaceRepository>,
}

struct NormalizedRoleSelection {
    role_kind: WorkspaceRoleKind,
    system_role: Option<WorkspaceSystemRole>,
    custom_role_id: Option<Uuid>,
    permissions: PermissionSet,
}

impl WorkspaceService {
    pub fn new(repo: Arc<dyn WorkspaceRepository>) -> Self {
        Self { repo }
    }

    pub async fn list_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<WorkspaceListItem>, ServiceError> {
        self.repo
            .list_for_user(user_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn create_workspace(
        &self,
        creator_id: Uuid,
        name: &str,
        icon: Option<&str>,
        description: Option<&str>,
    ) -> Result<WorkspaceRow, ServiceError> {
        let slug = slug::generate_slug(name);
        let workspace = self
            .repo
            .create_workspace(creator_id, name, &slug, icon, description, false)
            .await
            .map_err(ServiceError::from)?;
        // Creator becomes owner in the new workspace (default selection handled separately)
        let _member = self
            .repo
            .add_member(
                workspace.id,
                creator_id,
                WorkspaceRoleKind::System,
                Some(WorkspaceSystemRole::Owner),
                None,
            )
            .await
            .map_err(ServiceError::from)?;
        Ok(workspace)
    }

    pub async fn create_personal_workspace_shell(
        &self,
        user_id: Uuid,
        name: &str,
    ) -> Result<WorkspaceRow, ServiceError> {
        let slug = slug::generate_slug(name);
        self.repo
            .create_workspace_with_id(user_id, None, name, &slug, None, None, true)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn get_workspace(
        &self,
        workspace_id: Uuid,
    ) -> Result<Option<WorkspaceRow>, ServiceError> {
        self.repo
            .get_workspace(workspace_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn ensure_owner_membership(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), ServiceError> {
        self.repo
            .add_member(
                workspace_id,
                user_id,
                WorkspaceRoleKind::System,
                Some(WorkspaceSystemRole::Owner),
                None,
            )
            .await
            .map_err(ServiceError::from)?;
        self.repo
            .set_default_workspace(user_id, workspace_id)
            .await
            .map_err(Self::map_set_default_error)?;
        Ok(())
    }

    pub async fn delete_workspace(&self, workspace_id: Uuid) -> Result<bool, ServiceError> {
        self.repo
            .delete_workspace(workspace_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn update_workspace(
        &self,
        workspace_id: Uuid,
        name: Option<&str>,
        icon: Option<&str>,
        description: Option<&str>,
    ) -> Result<Option<WorkspaceRow>, ServiceError> {
        self.repo
            .update_workspace(workspace_id, name, icon, description)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn create_invitation(
        &self,
        workspace_id: Uuid,
        invited_by: Uuid,
        email: &str,
        role_kind: WorkspaceRoleKind,
        system_role: Option<WorkspaceSystemRole>,
        custom_role_id: Option<Uuid>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<WorkspaceInvitationRecord, ServiceError> {
        let normalized_email = email.trim().to_lowercase();
        if normalized_email.is_empty() || !normalized_email.contains('@') {
            return Err(ServiceError::BadRequest("invalid_email"));
        }
        let inviter_permissions = self
            .resolve_permission_set(workspace_id, invited_by)
            .await?
            .ok_or(ServiceError::Forbidden)?;
        let selection = self
            .resolve_role_selection(workspace_id, role_kind, system_role, custom_role_id)
            .await?;
        Self::ensure_role_grant_allowed(&inviter_permissions, &selection.permissions)?;
        let token = Uuid::new_v4().to_string();
        self.repo
            .create_invitation(
                workspace_id,
                &normalized_email,
                selection.role_kind,
                selection.system_role,
                selection.custom_role_id,
                invited_by,
                &token,
                expires_at,
            )
            .await
            .map_err(ServiceError::from)
    }

    pub async fn list_invitations(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<WorkspaceInvitationRecord>, ServiceError> {
        self.repo
            .list_invitations(workspace_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn accept_invitation(
        &self,
        token: &str,
        user_id: Uuid,
        user_email: &str,
    ) -> Result<WorkspaceInvitationRecord, ServiceError> {
        if user_email.trim().is_empty() {
            return Err(ServiceError::BadRequest("missing_email"));
        }
        self.repo
            .accept_invitation(token, user_id, user_email)
            .await
            .map_err(|err| match err.to_string().as_str() {
                "invitation_not_found" => ServiceError::NotFound,
                "invitation_email_mismatch" => ServiceError::Forbidden,
                "invitation_revoked" | "invitation_expired" | "invitation_already_accepted" => {
                    ServiceError::BadRequest("invitation_unavailable")
                }
                other => ServiceError::Unexpected(anyhow!(other.to_string())),
            })
    }

    pub async fn revoke_invitation(
        &self,
        workspace_id: Uuid,
        invitation_id: Uuid,
    ) -> Result<WorkspaceInvitationRecord, ServiceError> {
        let Some(record) = self
            .repo
            .revoke_invitation(workspace_id, invitation_id)
            .await
            .map_err(ServiceError::from)?
        else {
            return Err(ServiceError::NotFound);
        };
        Ok(record)
    }

    pub async fn set_default_workspace(
        &self,
        user_id: Uuid,
        workspace_id: Uuid,
    ) -> Result<WorkspaceMemberRow, ServiceError> {
        self.repo
            .set_default_workspace(user_id, workspace_id)
            .await
            .map_err(Self::map_set_default_error)
    }

    pub async fn resolve_permission_set(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<PermissionSet>, ServiceError> {
        let record = self
            .repo
            .get_member_with_permissions(workspace_id, user_id)
            .await
            .map_err(ServiceError::from)?;
        let Some(record) = record else {
            return Ok(None);
        };
        let mut set = match record.role_kind {
            WorkspaceRoleKind::System => {
                let role = record.system_role.unwrap_or(WorkspaceSystemRole::Viewer);
                system_role_permissions(role.as_str())
            }
            WorkspaceRoleKind::Custom => {
                let base_role = record.custom_base_role.unwrap_or(WorkspaceBaseRole::Viewer);
                system_role_permissions(base_role.as_str())
            }
        };
        if !record.overrides.is_empty() {
            set = apply_custom_overrides(set, record.overrides.clone());
        }
        Ok(Some(set))
    }

    pub async fn list_members(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<WorkspaceMemberDetail>, ServiceError> {
        self.repo
            .list_members(workspace_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn remove_member(
        &self,
        workspace_id: Uuid,
        member_id: Uuid,
        requested_by: Option<Uuid>,
    ) -> Result<(), ServiceError> {
        self.remove_member_internal(workspace_id, member_id, requested_by, false)
            .await
    }

    pub async fn leave_workspace(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), ServiceError> {
        self.remove_member_internal(workspace_id, user_id, Some(user_id), true)
            .await
    }

    async fn remove_member_internal(
        &self,
        workspace_id: Uuid,
        member_id: Uuid,
        requested_by: Option<Uuid>,
        allow_self: bool,
    ) -> Result<(), ServiceError> {
        if !allow_self && requested_by == Some(member_id) {
            return Err(ServiceError::BadRequest("cannot_remove_self"));
        }
        let member = self
            .repo
            .get_member_detail(workspace_id, member_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        if member.workspace_id == member.user_id {
            return Err(ServiceError::BadRequest("cannot_remove_owner"));
        }
        let removing_owner = member.role_kind == WorkspaceRoleKind::System
            && member.system_role == Some(WorkspaceSystemRole::Owner);
        if removing_owner {
            let owner_count = self
                .repo
                .count_system_role_members(workspace_id, WorkspaceSystemRole::Owner)
                .await
                .map_err(ServiceError::from)?;
            if owner_count <= 1 {
                return Err(ServiceError::BadRequest("cannot_remove_last_owner"));
            }
        }
        // Ensure users whose default workspace was this one fall back to their personal workspace
        if member.is_default {
            self.repo
                .set_default_workspace(member.user_id, member.user_id)
                .await
                .map_err(Self::map_set_default_error)?;
        }
        let removed = self
            .repo
            .delete_member(workspace_id, member_id)
            .await
            .map_err(ServiceError::from)?;
        if removed {
            Ok(())
        } else {
            Err(ServiceError::NotFound)
        }
    }

    pub async fn update_member_role(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        requested_by: Uuid,
        role_kind: WorkspaceRoleKind,
        system_role: Option<WorkspaceSystemRole>,
        custom_role_id: Option<Uuid>,
    ) -> Result<WorkspaceMemberRow, ServiceError> {
        let actor_permissions = self
            .resolve_permission_set(workspace_id, requested_by)
            .await?
            .ok_or(ServiceError::Forbidden)?;
        let selection = self
            .resolve_role_selection(workspace_id, role_kind, system_role, custom_role_id)
            .await?;
        Self::ensure_role_grant_allowed(&actor_permissions, &selection.permissions)?;
        self.repo
            .update_member_role(
                workspace_id,
                user_id,
                selection.role_kind,
                selection.system_role,
                selection.custom_role_id,
            )
            .await
            .map_err(ServiceError::from)
    }

    pub async fn list_roles(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<WorkspaceRoleRecord>, ServiceError> {
        self.repo
            .list_roles(workspace_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn create_role(
        &self,
        workspace_id: Uuid,
        requested_by: Uuid,
        name: &str,
        base_role: WorkspaceBaseRole,
        description: Option<&str>,
        priority: i32,
        overrides: &[PermissionOverride],
    ) -> Result<WorkspaceRoleRecord, ServiceError> {
        let actor_permissions = self
            .resolve_permission_set(workspace_id, requested_by)
            .await?
            .ok_or(ServiceError::Forbidden)?;
        let role_permissions = Self::permission_set_from_definition(base_role, overrides)?;
        Self::ensure_role_grant_allowed(&actor_permissions, &role_permissions)?;
        self.repo
            .create_role(
                workspace_id,
                name,
                base_role,
                description,
                priority,
                overrides,
            )
            .await
            .map_err(ServiceError::from)
    }

    pub async fn update_role(
        &self,
        workspace_id: Uuid,
        requested_by: Uuid,
        role_id: Uuid,
        name: Option<&str>,
        base_role: Option<WorkspaceBaseRole>,
        description: Option<&str>,
        priority: Option<i32>,
        overrides: Option<&[PermissionOverride]>,
    ) -> Result<WorkspaceRoleRecord, ServiceError> {
        let actor_permissions = self
            .resolve_permission_set(workspace_id, requested_by)
            .await?
            .ok_or(ServiceError::Forbidden)?;
        let existing = self
            .repo
            .get_role(workspace_id, role_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        let effective_base_role = base_role.unwrap_or(existing.base_role);
        let effective_overrides = overrides
            .map(|items| items.to_vec())
            .unwrap_or_else(|| existing.overrides.clone());
        let role_permissions =
            Self::permission_set_from_definition(effective_base_role, &effective_overrides)?;
        Self::ensure_role_grant_allowed(&actor_permissions, &role_permissions)?;
        self.repo
            .update_role(
                workspace_id,
                role_id,
                name,
                base_role,
                description,
                priority,
                overrides,
            )
            .await
            .map_err(ServiceError::from)
    }

    pub async fn delete_role(
        &self,
        workspace_id: Uuid,
        role_id: Uuid,
    ) -> Result<bool, ServiceError> {
        self.repo
            .delete_role(workspace_id, role_id)
            .await
            .map_err(ServiceError::from)
    }

    fn map_set_default_error(err: WorkspaceSetDefaultError) -> ServiceError {
        match err {
            WorkspaceSetDefaultError::MembershipNotFound => ServiceError::Forbidden,
            WorkspaceSetDefaultError::Unexpected(inner) => ServiceError::Unexpected(inner),
        }
    }

    fn ensure_role_grant_allowed(
        actor_permissions: &PermissionSet,
        target_permissions: &PermissionSet,
    ) -> Result<(), ServiceError> {
        if actor_permissions.contains_all(target_permissions) {
            Ok(())
        } else {
            Err(ServiceError::Forbidden)
        }
    }

    async fn resolve_role_selection(
        &self,
        workspace_id: Uuid,
        role_kind: WorkspaceRoleKind,
        system_role: Option<WorkspaceSystemRole>,
        custom_role_id: Option<Uuid>,
    ) -> Result<NormalizedRoleSelection, ServiceError> {
        match role_kind {
            WorkspaceRoleKind::System => {
                if custom_role_id.is_some() {
                    return Err(ServiceError::BadRequest("unexpected_custom_role"));
                }
                let Some(role) = system_role else {
                    return Err(ServiceError::BadRequest("missing_system_role"));
                };
                Ok(NormalizedRoleSelection {
                    role_kind: WorkspaceRoleKind::System,
                    system_role: Some(role),
                    custom_role_id: None,
                    permissions: system_role_permissions(role.as_str()),
                })
            }
            WorkspaceRoleKind::Custom => {
                if system_role.is_some() {
                    return Err(ServiceError::BadRequest("unexpected_system_role"));
                }
                let Some(role_id) = custom_role_id else {
                    return Err(ServiceError::BadRequest("missing_custom_role"));
                };
                let Some(record) = self
                    .repo
                    .get_role(workspace_id, role_id)
                    .await
                    .map_err(ServiceError::from)?
                else {
                    return Err(ServiceError::BadRequest("invalid_custom_role"));
                };
                let mut permissions = system_role_permissions(record.base_role.as_str());
                if !record.overrides.is_empty() {
                    permissions = apply_custom_overrides(permissions, record.overrides.clone());
                }
                Ok(NormalizedRoleSelection {
                    role_kind: WorkspaceRoleKind::Custom,
                    system_role: None,
                    custom_role_id: Some(role_id),
                    permissions,
                })
            }
        }
    }

    fn permission_set_from_definition(
        base_role: WorkspaceBaseRole,
        overrides: &[PermissionOverride],
    ) -> Result<PermissionSet, ServiceError> {
        let mut permissions = system_role_permissions(base_role.as_str());
        if !overrides.is_empty() {
            permissions = apply_custom_overrides(permissions, overrides.to_vec());
        }
        Ok(permissions)
    }
}

#[async_trait]
impl WorkspacePermissionResolver for WorkspaceService {
    async fn load_permission_set(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<PermissionSet>, ServiceError> {
        WorkspaceService::resolve_permission_set(self, workspace_id, user_id).await
    }
}
