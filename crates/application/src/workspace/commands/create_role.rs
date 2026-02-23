//! Create workspace role command
//!
//! Creates a custom role in a workspace. Requires role:manage permission.

use crate::dto::WorkspaceRoleDto;
use crate::util::workspace_access::{WorkspaceAccessError, check_workspace_permission};
use domain::identity::UserId;
use domain::workspace::{
    BaseRole, WorkspaceId, WorkspaceMemberRepository, WorkspaceRole,
    WorkspaceRolePermissionRepository, WorkspaceRoleRepository, permission,
};
use std::sync::Arc;
use thiserror::Error;

/// Create role command
#[derive(Debug)]
pub struct CreateRoleCommand {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub name: String,
    pub base_role: BaseRole,
    pub is_default: bool,
}

/// Create role result
#[derive(Debug)]
pub struct CreateRoleResult {
    pub role: WorkspaceRoleDto,
}

/// Create role error
#[derive(Debug, Error)]
pub enum CreateRoleError<MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error> {
    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

    #[error("role name is empty")]
    EmptyName,

    #[error("role name is too long (max 50 characters)")]
    NameTooLong,

    #[error("cannot create a role with Owner base role")]
    CannotCreateOwnerRole,

    #[error("only the workspace owner can set the default role")]
    OwnerOnlyOperation,

    #[error("role repository error: {0}")]
    RoleRepository(RR),
}

crate::types::impl_app_error!(
    [MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error]
    CreateRoleError<MR, RR, RPR>,
    not_found: [
        CreateRoleError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        CreateRoleError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
        CreateRoleError::OwnerOnlyOperation,
    ],
    invalid_input: [
        CreateRoleError::EmptyName,
        CreateRoleError::NameTooLong,
        CreateRoleError::CannotCreateOwnerRole,
    ],
);

/// Create role handler
pub struct CreateRoleHandler<MR: ?Sized, RR: ?Sized, RPR: ?Sized> {
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
}

impl<MR: ?Sized, RR: ?Sized, RPR: ?Sized> CreateRoleHandler<MR, RR, RPR>
where
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    RPR: WorkspaceRolePermissionRepository,
{
    pub fn new(member_repo: Arc<MR>, role_repo: Arc<RR>, role_perm_repo: Arc<RPR>) -> Self {
        Self {
            member_repo,
            role_repo,
            role_perm_repo,
        }
    }

    pub async fn handle(
        &self,
        command: CreateRoleCommand,
    ) -> Result<CreateRoleResult, CreateRoleError<MR::Error, RR::Error, RPR::Error>> {
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
        .map_err(CreateRoleError::WorkspaceAccess)?;

        // 2. Validate name
        let name = command.name.trim().to_string();
        if name.is_empty() {
            return Err(CreateRoleError::EmptyName);
        }
        if name.len() > 50 {
            return Err(CreateRoleError::NameTooLong);
        }

        // 3. Cannot create Owner base_role
        if command.base_role == BaseRole::Owner {
            return Err(CreateRoleError::CannotCreateOwnerRole);
        }

        // 4. Only Owner can set is_default
        if command.is_default && actor.role.base_role != BaseRole::Owner {
            return Err(CreateRoleError::OwnerOnlyOperation);
        }

        // 5. Create role
        let mut role = WorkspaceRole::new(command.workspace_id, name, command.base_role, false);

        if command.is_default {
            // 5a. Atomically create + set as default in one transaction
            self.role_repo
                .save_and_set_default(&role)
                .await
                .map_err(CreateRoleError::RoleRepository)?;
            role.is_default = true;
        } else {
            // 5b. Simple creation (no default swap needed)
            self.role_repo
                .save(&role)
                .await
                .map_err(CreateRoleError::RoleRepository)?;
        }

        Ok(CreateRoleResult {
            role: role.into(),
        })
    }
}
