//! Create workspace command
//!
//! Creates a new workspace with default roles (Owner, Admin, Editor, Viewer)
//! and adds the creating user as the Owner member.
//! Uses a transactional service to persist all entities atomically.

use crate::dto::{WorkspaceDto, WorkspaceMemberDto, WorkspaceRoleDto};
use crate::util::slug::{ensure_unique_workspace_slug, generate_workspace_slug};
use domain::identity::UserId;
use domain::workspace::{
    Workspace, WorkspaceMember, WorkspaceRepository, WorkspaceRole,
};
use std::sync::Arc;
use thiserror::Error;

use super::super::services::{WorkspaceCreationData, WorkspaceCreationService, WorkspaceCreationServiceError};

/// Create workspace command
#[derive(Debug)]
pub struct CreateWorkspaceCommand {
    pub user_id: UserId,
    pub name: String,
    pub description: Option<String>,
}

/// Create workspace result
#[derive(Debug)]
pub struct CreateWorkspaceResult {
    pub workspace: WorkspaceDto,
    pub membership: WorkspaceMemberDto,
    pub role: WorkspaceRoleDto,
}

/// Create workspace error
#[derive(Debug, Error)]
pub enum CreateWorkspaceError<WR: std::error::Error> {
    #[error("workspace name is empty")]
    EmptyName,

    #[error("workspace name is too long (max 100 characters)")]
    NameTooLong,

    #[error("could not generate a unique slug")]
    SlugExhausted,

    #[error("workspace slug already exists")]
    SlugConflict,

    #[error("workspace repository error: {0}")]
    WorkspaceRepository(WR),

    #[error("creation service error: {0}")]
    CreationService(#[from] WorkspaceCreationServiceError),
}

crate::types::impl_app_error!(
    [WR: std::error::Error]
    CreateWorkspaceError<WR>,
    invalid_input: [
        CreateWorkspaceError::EmptyName,
        CreateWorkspaceError::NameTooLong,
    ],
    conflict: [
        CreateWorkspaceError::SlugExhausted,
        CreateWorkspaceError::SlugConflict,
    ],
);

/// Create workspace handler
pub struct CreateWorkspaceHandler<WR: ?Sized> {
    workspace_repo: Arc<WR>,
    creation_service: Arc<dyn WorkspaceCreationService>,
}

impl<WR: ?Sized> CreateWorkspaceHandler<WR>
where
    WR: WorkspaceRepository,
{
    pub fn new(
        workspace_repo: Arc<WR>,
        creation_service: Arc<dyn WorkspaceCreationService>,
    ) -> Self {
        Self {
            workspace_repo,
            creation_service,
        }
    }

    pub async fn handle(
        &self,
        command: CreateWorkspaceCommand,
    ) -> Result<CreateWorkspaceResult, CreateWorkspaceError<WR::Error>> {
        // 1. Validate name
        let name = command.name.trim().to_string();
        if name.is_empty() {
            return Err(CreateWorkspaceError::EmptyName);
        }
        if name.len() > 100 {
            return Err(CreateWorkspaceError::NameTooLong);
        }

        // 2. Generate unique slug
        let base_slug = generate_workspace_slug(&name)
            .map_err(|_| CreateWorkspaceError::SlugExhausted)?;
        let slug = ensure_unique_workspace_slug(&self.workspace_repo, base_slug)
            .await
            .map_err(CreateWorkspaceError::WorkspaceRepository)?
            .ok_or(CreateWorkspaceError::SlugExhausted)?;

        // 3. Build all entities
        let description = command.description.map(|d| d.trim().to_string()).filter(|d| !d.is_empty());
        let workspace = Workspace::new(name, slug, command.user_id, description);
        let owner_role = WorkspaceRole::owner(workspace.id);
        let admin_role = WorkspaceRole::admin(workspace.id);
        let editor_role = WorkspaceRole::editor(workspace.id);
        let viewer_role = WorkspaceRole::viewer(workspace.id);
        let member = WorkspaceMember::new_owner(workspace.id, command.user_id, owner_role.id);

        // 4. Persist atomically
        let result_workspace = workspace.clone();
        let result_member = member.clone();
        let result_role = owner_role.clone();

        self.creation_service
            .create_atomic(WorkspaceCreationData {
                workspace,
                owner_role,
                admin_role,
                editor_role,
                viewer_role,
                member,
            })
            .await
            .map_err(|e| match e {
                WorkspaceCreationServiceError::SlugConflict => {
                    CreateWorkspaceError::SlugConflict
                }
                other => CreateWorkspaceError::CreationService(other),
            })?;

        Ok(CreateWorkspaceResult {
            workspace: result_workspace.into(),
            membership: result_member.into(),
            role: result_role.into(),
        })
    }
}
