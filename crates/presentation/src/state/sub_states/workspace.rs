use application::types::{BoxedError as BE, WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRoleRepository};
use std::sync::Arc;

use super::*;

/// Sub-state for workspace-related routes
#[derive(Clone)]
pub struct WorkspaceSubState {
    pub workspace_repo: DynWorkspaceRepository,
    pub workspace_member_repo: DynWorkspaceMemberRepository,
    pub workspace_role_repo: DynWorkspaceRoleRepository,
}

impl WorkspaceSubState {
    pub fn list_workspaces_handler(
        &self,
    ) -> application::workspace::ListUserWorkspacesHandler<
        dyn WorkspaceRepository<Error = BE>,
        dyn WorkspaceMemberRepository<Error = BE>,
        dyn WorkspaceRoleRepository<Error = BE>,
    > {
        application::workspace::ListUserWorkspacesHandler::new(
            self.workspace_repo.clone(),
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
        )
    }

    pub fn get_workspace_handler(
        &self,
    ) -> application::workspace::GetWorkspaceHandler<
        dyn WorkspaceRepository<Error = BE>,
        dyn WorkspaceMemberRepository<Error = BE>,
        dyn WorkspaceRoleRepository<Error = BE>,
    > {
        application::workspace::GetWorkspaceHandler::new(
            self.workspace_repo.clone(),
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
        )
    }
}

impl_from_ref!(WorkspaceSubState {
    workspace_repo, workspace_member_repo, workspace_role_repo,
});
