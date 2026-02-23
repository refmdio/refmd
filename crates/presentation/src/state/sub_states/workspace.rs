use application::types::{
    BoxedError as BE, UserRepository, WorkspaceInvitationRepository,
    WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRolePermissionRepository,
    WorkspaceRoleRepository,
};
use std::sync::Arc;

use super::*;

// Handler type aliases (clippy::type_complexity)
type DynUpdateWorkspaceHandler = application::workspace::UpdateWorkspaceHandler<
    dyn WorkspaceRepository<Error = BE>,
    dyn WorkspaceMemberRepository<Error = BE>,
    dyn WorkspaceRoleRepository<Error = BE>,
    dyn WorkspaceRolePermissionRepository<Error = BE>,
>;

type DynDeleteWorkspaceHandler = application::workspace::DeleteWorkspaceHandler<
    dyn WorkspaceRepository<Error = BE>,
    dyn WorkspaceMemberRepository<Error = BE>,
    dyn WorkspaceRoleRepository<Error = BE>,
    dyn WorkspaceRolePermissionRepository<Error = BE>,
>;

type DynListRolesHandler = application::workspace::ListRolesHandler<
    dyn WorkspaceMemberRepository<Error = BE>,
    dyn WorkspaceRoleRepository<Error = BE>,
    dyn WorkspaceRolePermissionRepository<Error = BE>,
>;

type DynCreateRoleHandler = application::workspace::CreateRoleHandler<
    dyn WorkspaceMemberRepository<Error = BE>,
    dyn WorkspaceRoleRepository<Error = BE>,
    dyn WorkspaceRolePermissionRepository<Error = BE>,
>;

type DynUpdateRoleHandler = application::workspace::UpdateRoleHandler<
    dyn WorkspaceMemberRepository<Error = BE>,
    dyn WorkspaceRoleRepository<Error = BE>,
    dyn WorkspaceRolePermissionRepository<Error = BE>,
>;

type DynDeleteRoleHandler = application::workspace::DeleteRoleHandler<
    dyn WorkspaceMemberRepository<Error = BE>,
    dyn WorkspaceRoleRepository<Error = BE>,
    dyn WorkspaceRolePermissionRepository<Error = BE>,
    dyn WorkspaceInvitationRepository<Error = BE>,
>;

type DynListMembersHandler = application::workspace::ListMembersHandler<
    dyn WorkspaceMemberRepository<Error = BE>,
    dyn WorkspaceRoleRepository<Error = BE>,
    dyn WorkspaceRolePermissionRepository<Error = BE>,
    dyn UserRepository<Error = BE>,
>;

type DynChangeMemberRoleHandler = application::workspace::ChangeMemberRoleHandler<
    dyn WorkspaceMemberRepository<Error = BE>,
    dyn WorkspaceRoleRepository<Error = BE>,
    dyn WorkspaceRolePermissionRepository<Error = BE>,
>;

type DynRemoveMemberHandler = application::workspace::RemoveMemberHandler<
    dyn WorkspaceMemberRepository<Error = BE>,
    dyn WorkspaceRoleRepository<Error = BE>,
    dyn WorkspaceRolePermissionRepository<Error = BE>,
    dyn application::types::DocumentRepository<Error = BE>,
    dyn application::types::DocumentEncryptedKeyRepository<Error = BE>,
>;

type DynCreateInvitationHandler = application::workspace::CreateInvitationHandler<
    dyn WorkspaceMemberRepository<Error = BE>,
    dyn WorkspaceRoleRepository<Error = BE>,
    dyn WorkspaceRolePermissionRepository<Error = BE>,
>;

type DynListInvitationsHandler = application::workspace::ListInvitationsHandler<
    dyn WorkspaceMemberRepository<Error = BE>,
    dyn WorkspaceRoleRepository<Error = BE>,
    dyn WorkspaceRolePermissionRepository<Error = BE>,
    dyn WorkspaceInvitationRepository<Error = BE>,
>;

type DynRevokeInvitationHandler = application::workspace::RevokeInvitationHandler<
    dyn WorkspaceMemberRepository<Error = BE>,
    dyn WorkspaceRoleRepository<Error = BE>,
    dyn WorkspaceRolePermissionRepository<Error = BE>,
    dyn WorkspaceInvitationRepository<Error = BE>,
>;

/// Sub-state for workspace-related routes
#[derive(Clone)]
pub struct WorkspaceSubState {
    pub workspace_repo: DynWorkspaceRepository,
    pub workspace_member_repo: DynWorkspaceMemberRepository,
    pub workspace_role_repo: DynWorkspaceRoleRepository,
    pub workspace_role_perm_repo: DynWorkspaceRolePermissionRepository,
    pub workspace_invitation_repo: DynWorkspaceInvitationRepository,
    pub workspace_creation_service: DynWorkspaceCreationService,
    pub invitation_acceptance_service: DynInvitationAcceptanceService,
    pub invitation_creation_service: DynInvitationCreationService,
    pub member_mutation_service: DynMemberMutationService,
    pub document_repo: DynDocumentRepository,
    pub document_key_repo: DynDocumentEncryptedKeyRepository,
    pub rotation_marking_service: DynRotationMarkingService,
    pub role_update_service: DynRoleUpdateService,
    pub user_repo: DynUserRepository,
    pub workspace_event_bus: DynWorkspaceEventBus,
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

    pub fn create_workspace_handler(
        &self,
    ) -> application::workspace::CreateWorkspaceHandler<dyn WorkspaceRepository<Error = BE>> {
        application::workspace::CreateWorkspaceHandler::new(
            self.workspace_repo.clone(),
            self.workspace_creation_service.clone(),
        )
    }

    pub fn update_workspace_handler(&self) -> DynUpdateWorkspaceHandler {
        application::workspace::UpdateWorkspaceHandler::new(
            self.workspace_repo.clone(),
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
            self.workspace_role_perm_repo.clone(),
        )
    }

    pub fn delete_workspace_handler(&self) -> DynDeleteWorkspaceHandler {
        application::workspace::DeleteWorkspaceHandler::new(
            self.workspace_repo.clone(),
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
            self.workspace_role_perm_repo.clone(),
        )
    }

    pub fn list_roles_handler(&self) -> DynListRolesHandler {
        application::workspace::ListRolesHandler::new(
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
            self.workspace_role_perm_repo.clone(),
        )
    }

    pub fn create_role_handler(&self) -> DynCreateRoleHandler {
        application::workspace::CreateRoleHandler::new(
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
            self.workspace_role_perm_repo.clone(),
        )
    }

    pub fn update_role_handler(&self) -> DynUpdateRoleHandler {
        application::workspace::UpdateRoleHandler::new(
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
            self.workspace_role_perm_repo.clone(),
            self.role_update_service.clone(),
        )
    }

    pub fn delete_role_handler(&self) -> DynDeleteRoleHandler {
        application::workspace::DeleteRoleHandler::new(
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
            self.workspace_role_perm_repo.clone(),
            self.workspace_invitation_repo.clone(),
        )
    }

    pub fn list_members_handler(&self) -> DynListMembersHandler {
        application::workspace::ListMembersHandler::new(
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
            self.workspace_role_perm_repo.clone(),
            self.user_repo.clone(),
        )
    }

    pub fn change_member_role_handler(&self) -> DynChangeMemberRoleHandler {
        application::workspace::ChangeMemberRoleHandler::new(
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
            self.workspace_role_perm_repo.clone(),
            self.member_mutation_service.clone(),
        )
    }

    pub fn remove_member_handler(&self) -> DynRemoveMemberHandler {
        application::workspace::RemoveMemberHandler::new(
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
            self.workspace_role_perm_repo.clone(),
            self.member_mutation_service.clone(),
            self.document_repo.clone(),
            self.document_key_repo.clone(),
            self.rotation_marking_service.clone(),
        )
    }

    pub fn create_invitation_handler(&self) -> DynCreateInvitationHandler {
        application::workspace::CreateInvitationHandler::new(
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
            self.workspace_role_perm_repo.clone(),
            self.invitation_creation_service.clone(),
        )
    }

    pub fn list_invitations_handler(&self) -> DynListInvitationsHandler {
        application::workspace::ListInvitationsHandler::new(
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
            self.workspace_role_perm_repo.clone(),
            self.workspace_invitation_repo.clone(),
        )
    }

    pub fn revoke_invitation_handler(&self) -> DynRevokeInvitationHandler {
        application::workspace::RevokeInvitationHandler::new(
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
            self.workspace_role_perm_repo.clone(),
            self.workspace_invitation_repo.clone(),
        )
    }

    pub fn accept_invitation_handler(
        &self,
    ) -> application::workspace::AcceptInvitationHandler<
        dyn UserRepository<Error = BE>,
        dyn WorkspaceMemberRepository<Error = BE>,
    > {
        application::workspace::AcceptInvitationHandler::new(
            self.user_repo.clone(),
            self.workspace_member_repo.clone(),
            self.invitation_acceptance_service.clone(),
            self.workspace_event_bus.clone(),
        )
    }
}

impl_from_ref!(WorkspaceSubState {
    workspace_repo, workspace_member_repo, workspace_role_repo, workspace_role_perm_repo,
    workspace_invitation_repo, workspace_creation_service,
    invitation_acceptance_service, invitation_creation_service, member_mutation_service,
    document_repo, document_key_repo, rotation_marking_service, role_update_service, user_repo,
    workspace_event_bus,
});
