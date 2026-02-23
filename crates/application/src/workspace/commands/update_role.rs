//! Update workspace role command
//!
//! Updates a role's name, is_default, and permission overrides.
//! Requires role:manage permission. base_role is immutable after creation.

use crate::dto::WorkspaceRoleDto;
use crate::util::workspace_access::{WorkspaceAccessError, check_workspace_permission};
use crate::workspace::RoleUpdateService;
use domain::identity::UserId;
use domain::workspace::{
    BaseRole, RoleId, WorkspaceId, WorkspaceMemberRepository,
    WorkspaceRolePermissionRepository, WorkspaceRoleRepository, permission,
};
use std::sync::Arc;
use thiserror::Error;

/// Update role command
#[derive(Debug)]
pub struct UpdateRoleCommand {
    pub workspace_id: WorkspaceId,
    pub role_id: RoleId,
    pub user_id: UserId,
    pub name: Option<String>,
    pub is_default: Option<bool>,
    /// Permission overrides: (permission_name, granted)
    pub permission_overrides: Option<Vec<(String, bool)>>,
}

/// Update role result
#[derive(Debug)]
pub struct UpdateRoleResult {
    pub role: WorkspaceRoleDto,
}

/// Update role error
#[derive(Debug, Error)]
pub enum UpdateRoleError<MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error> {
    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

    #[error("role not found")]
    RoleNotFound,

    #[error("role does not belong to this workspace")]
    RoleWorkspaceMismatch,

    #[error("role name is empty")]
    EmptyName,

    #[error("role name is too long (max 50 characters)")]
    NameTooLong,

    #[error("only the workspace owner can change the default role")]
    OwnerOnlyOperation,

    #[error("unknown permission: {0}")]
    UnknownPermission(String),

    #[error("cannot unset the default role — set another role as default instead")]
    CannotUnsetDefault,

    #[error("duplicate permission: {0}")]
    DuplicatePermission(String),

    #[error("permission {permission} cannot be granted to role with base_role {base_role}")]
    PermissionExceedsCeiling {
        permission: String,
        base_role: String,
    },

    #[error("role repository error: {0}")]
    RoleRepository(RR),

    #[error("role permission repository error: {0}")]
    RolePermissionRepository(RPR),

    #[error("update service error: {0}")]
    UpdateService(String),
}

crate::types::impl_app_error!(
    [MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error]
    UpdateRoleError<MR, RR, RPR>,
    not_found: [
        UpdateRoleError::RoleNotFound,
        UpdateRoleError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        UpdateRoleError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
        UpdateRoleError::OwnerOnlyOperation,
        UpdateRoleError::RoleWorkspaceMismatch,
    ],
    invalid_input: [
        UpdateRoleError::EmptyName,
        UpdateRoleError::NameTooLong,
        UpdateRoleError::CannotUnsetDefault,
        UpdateRoleError::UnknownPermission(..),
        UpdateRoleError::DuplicatePermission(..),
        UpdateRoleError::PermissionExceedsCeiling { .. },
    ],
);

/// Update role handler
pub struct UpdateRoleHandler<MR: ?Sized, RR: ?Sized, RPR: ?Sized> {
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
    role_update_service: Arc<dyn RoleUpdateService>,
}

impl<MR: ?Sized, RR: ?Sized, RPR: ?Sized> UpdateRoleHandler<MR, RR, RPR>
where
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    RPR: WorkspaceRolePermissionRepository,
{
    pub fn new(
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
        role_perm_repo: Arc<RPR>,
        role_update_service: Arc<dyn RoleUpdateService>,
    ) -> Self {
        Self {
            member_repo,
            role_repo,
            role_perm_repo,
            role_update_service,
        }
    }

    pub async fn handle(
        &self,
        command: UpdateRoleCommand,
    ) -> Result<UpdateRoleResult, UpdateRoleError<MR::Error, RR::Error, RPR::Error>> {
        // 1. Permission check
        let actor = check_workspace_permission(
            &self.member_repo,
            &self.role_repo,
            &self.role_perm_repo,
            command.workspace_id,
            command.user_id,
            permission::ROLE_MANAGE,
        )
        .await
        .map_err(UpdateRoleError::WorkspaceAccess)?;

        // 2. Load role
        let mut role = self
            .role_repo
            .find_by_id(command.role_id)
            .await
            .map_err(UpdateRoleError::RoleRepository)?
            .ok_or(UpdateRoleError::RoleNotFound)?;

        // 3. Verify role belongs to workspace
        if role.workspace_id != command.workspace_id {
            return Err(UpdateRoleError::RoleWorkspaceMismatch);
        }

        // 4. Compute trimmed name up front so all downstream code uses the same value
        let trimmed_name = command.name.as_ref().map(|n| n.trim().to_string());

        // 5. Validate and apply name
        if let Some(ref name) = trimmed_name {
            if name.is_empty() {
                return Err(UpdateRoleError::EmptyName);
            }
            if name.len() > 50 {
                return Err(UpdateRoleError::NameTooLong);
            }
            role.name = name.clone();
        }

        // 6. Handle is_default change (Owner only)
        // Design doc: swap old default→false + new→true in same transaction
        let mut needs_default_swap = false;
        if let Some(is_default) = command.is_default {
            if actor.role.base_role != BaseRole::Owner {
                return Err(UpdateRoleError::OwnerOnlyOperation);
            }
            if is_default && !role.is_default {
                needs_default_swap = true;
                role.is_default = true;
            } else if !is_default && role.is_default {
                // Cannot unset default without setting another role as default
                return Err(UpdateRoleError::CannotUnsetDefault);
            }
            // is_default == current → no-op
        }

        // 7. Validate permission overrides (within ceiling)
        if let Some(ref overrides) = command.permission_overrides {
            let mut seen = std::collections::HashSet::new();
            for (perm, granted) in overrides {
                if !seen.insert(perm.as_str()) {
                    return Err(UpdateRoleError::DuplicatePermission(perm.clone()));
                }
                if !permission::is_valid_permission(perm) {
                    return Err(UpdateRoleError::UnknownPermission(perm.clone()));
                }
                // Ceiling check applies to grant overrides only.
                // Revoking a permission above the ceiling is harmless (the role
                // wouldn't have it anyway) and is permitted per design doc.
                if *granted {
                    if permission::ceiling(perm)
                        .is_some_and(|ceil| !permission::is_at_or_above(role.base_role, ceil))
                    {
                        return Err(UpdateRoleError::PermissionExceedsCeiling {
                            permission: perm.clone(),
                            base_role: role.base_role.to_string(),
                        });
                    }
                }
            }
        }

        // 8. Atomically apply all changes (permissions + metadata + default swap)
        //    in a single transaction via RoleUpdateService.
        use crate::workspace::RoleUpdateError;

        let has_changes = command.permission_overrides.is_some()
            || needs_default_swap
            || trimmed_name.is_some();

        if has_changes {
            self.role_update_service
                .update_role_atomic(
                    command.workspace_id,
                    command.role_id,
                    trimmed_name.as_deref(),
                    needs_default_swap,
                    command.permission_overrides.as_deref(),
                )
                .await
                .map_err(|e| match e {
                    RoleUpdateError::RoleNotFound => UpdateRoleError::RoleNotFound,
                    RoleUpdateError::Database(msg) => UpdateRoleError::UpdateService(msg),
                })?;
        }

        // Always re-read persisted overrides for the response
        let saved_overrides = self.role_perm_repo
            .find_by_role_id(role.id)
            .await
            .map_err(UpdateRoleError::RolePermissionRepository)?
            .into_iter()
            .map(|o| (o.permission, o.granted))
            .collect();

        let mut dto: WorkspaceRoleDto = role.into();
        dto.permission_overrides = saved_overrides;
        Ok(UpdateRoleResult { role: dto })
    }
}
