use std::sync::Arc;

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub mod permissions;

use self::permissions::{PermissionSet, apply_custom_overrides, system_role_permissions};
use crate::application::ports::workspace_repository::{
    WorkspaceInvitationRecord, WorkspaceListItem, WorkspaceMemberDetail, WorkspaceMemberRow,
    WorkspaceRepository, WorkspaceRoleRecord, WorkspaceRow,
};
use crate::application::services::errors::ServiceError;

pub struct WorkspaceService {
    repo: Arc<dyn WorkspaceRepository>,
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
        let slug = self.generate_slug(name);
        let workspace = self
            .repo
            .create_workspace(creator_id, name, &slug, icon, description, false)
            .await
            .map_err(ServiceError::from)?;
        // Creator becomes owner in the new workspace (default selection handled separately)
        let _member = self
            .repo
            .add_member(workspace.id, creator_id, "system", Some("owner"), None)
            .await
            .map_err(ServiceError::from)?;
        Ok(workspace)
    }

    pub async fn create_personal_workspace_shell(
        &self,
        user_id: Uuid,
        name: &str,
    ) -> Result<WorkspaceRow, ServiceError> {
        let slug = self.generate_slug(name);
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
            .add_member(workspace_id, user_id, "system", Some("owner"), None)
            .await
            .map_err(ServiceError::from)?;
        self.repo
            .set_default_workspace(user_id, workspace_id)
            .await
            .map_err(ServiceError::from)?;
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
        role_kind: &str,
        system_role: Option<&str>,
        custom_role_id: Option<Uuid>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<WorkspaceInvitationRecord, ServiceError> {
        let normalized_email = email.trim().to_lowercase();
        if normalized_email.is_empty() || !normalized_email.contains('@') {
            return Err(ServiceError::BadRequest("invalid_email"));
        }
        let (role_kind, system_role, custom_role_id) =
            Self::validate_role_selection(role_kind, system_role, custom_role_id)?;
        let token = Uuid::new_v4().to_string();
        self.repo
            .create_invitation(
                workspace_id,
                &normalized_email,
                &role_kind,
                system_role.as_deref(),
                custom_role_id,
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
            .map_err(ServiceError::from)
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
        let mut set = match record.role_kind.as_str() {
            "system" => {
                let role = record.system_role.as_deref().unwrap_or("viewer");
                system_role_permissions(role)
            }
            "custom" => {
                let base_role = record.custom_base_role.as_deref().unwrap_or("viewer");
                system_role_permissions(base_role)
            }
            _ => system_role_permissions("viewer"),
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
    ) -> Result<(), ServiceError> {
        let member = self
            .repo
            .get_member_detail(workspace_id, member_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        if member.workspace_id == member.user_id {
            return Err(ServiceError::BadRequest("cannot_remove_owner"));
        }
        // Ensure users whose default workspace was this one fall back to their personal workspace
        if member.is_default {
            self.repo
                .set_default_workspace(member.user_id, member.user_id)
                .await
                .map_err(ServiceError::from)?;
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
        role_kind: &str,
        system_role: Option<&str>,
        custom_role_id: Option<Uuid>,
    ) -> Result<WorkspaceMemberRow, ServiceError> {
        self.repo
            .update_member_role(
                workspace_id,
                user_id,
                role_kind,
                system_role,
                custom_role_id,
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
        name: &str,
        base_role: &str,
        description: Option<&str>,
        priority: i32,
        overrides: &[(String, bool)],
    ) -> Result<WorkspaceRoleRecord, ServiceError> {
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
        role_id: Uuid,
        name: Option<&str>,
        base_role: Option<&str>,
        description: Option<&str>,
        priority: Option<i32>,
        overrides: Option<&[(String, bool)]>,
    ) -> Result<WorkspaceRoleRecord, ServiceError> {
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

    fn validate_role_selection(
        role_kind: &str,
        system_role: Option<&str>,
        custom_role_id: Option<Uuid>,
    ) -> Result<(String, Option<String>, Option<Uuid>), ServiceError> {
        match role_kind {
            "system" => {
                let Some(role) = system_role else {
                    return Err(ServiceError::BadRequest("missing_system_role"));
                };
                if !matches!(role, "owner" | "admin" | "editor" | "viewer") {
                    return Err(ServiceError::BadRequest("invalid_system_role"));
                }
                Ok(("system".to_string(), Some(role.to_string()), None))
            }
            "custom" => {
                if custom_role_id.is_none() {
                    return Err(ServiceError::BadRequest("missing_custom_role"));
                }
                Ok(("custom".to_string(), None, custom_role_id))
            }
            _ => Err(ServiceError::BadRequest("invalid_role_kind")),
        }
    }

    fn generate_slug(&self, name: &str) -> String {
        let mut slug = name
            .trim()
            .to_lowercase()
            .chars()
            .map(|c| match c {
                'a'..='z' | '0'..='9' => c,
                _ => '-',
            })
            .collect::<String>();
        while slug.contains("--") {
            slug = slug.replace("--", "-");
        }
        let mut slug = slug
            .trim_matches('-')
            .chars()
            .take(40)
            .collect::<String>()
            .if_empty("workspace".to_string());
        let suffix = Uuid::new_v4().to_string();
        slug.push('-');
        slug.push_str(&suffix[..8]);
        slug
    }
}

trait IfEmpty {
    fn if_empty(self, fallback: impl Into<String>) -> String;
}

impl IfEmpty for String {
    fn if_empty(self, fallback: impl Into<String>) -> String {
        if self.is_empty() {
            fallback.into()
        } else {
            self
        }
    }
}
