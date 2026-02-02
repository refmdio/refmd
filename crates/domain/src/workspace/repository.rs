//! Workspace repository traits

use async_trait::async_trait;

use super::invitation::WorkspaceInvitation;
use super::member::WorkspaceMember;
use super::role::{WorkspaceRole, WorkspaceRolePermission};
use super::value_objects::{InvitationId, Permission, RoleId, Slug, WorkspaceId};
use super::workspace::Workspace;
use crate::identity::UserId;

/// Workspace repository trait
#[async_trait]
pub trait WorkspaceRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find workspace by ID
    async fn find_by_id(&self, id: WorkspaceId) -> Result<Option<Workspace>, Self::Error>;

    /// Find workspace by slug
    async fn find_by_slug(&self, slug: &Slug) -> Result<Option<Workspace>, Self::Error>;

    /// Find all workspaces owned by a user
    async fn find_by_owner_id(&self, owner_id: UserId) -> Result<Vec<Workspace>, Self::Error>;

    /// Check if slug exists
    async fn slug_exists(&self, slug: &Slug) -> Result<bool, Self::Error>;

    /// Save workspace
    async fn save(&self, workspace: &Workspace) -> Result<(), Self::Error>;

    /// Delete workspace
    async fn delete(&self, id: WorkspaceId) -> Result<(), Self::Error>;
}

/// Workspace member repository trait
#[async_trait]
pub trait WorkspaceMemberRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find member by workspace and user
    async fn find_by_workspace_and_user(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
    ) -> Result<Option<WorkspaceMember>, Self::Error>;

    /// Find all members of a workspace
    async fn find_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<WorkspaceMember>, Self::Error>;

    /// Find all workspaces a user is a member of
    async fn find_by_user_id(&self, user_id: UserId) -> Result<Vec<WorkspaceMember>, Self::Error>;

    /// Find user's default workspace
    async fn find_default_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Option<WorkspaceMember>, Self::Error>;

    /// Save member
    async fn save(&self, member: &WorkspaceMember) -> Result<(), Self::Error>;

    /// Delete member
    async fn delete(&self, workspace_id: WorkspaceId, user_id: UserId) -> Result<(), Self::Error>;

    /// Delete all members of a workspace
    async fn delete_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<(), Self::Error>;

    /// Clear default flag for all user's workspaces
    async fn clear_default_for_user(&self, user_id: UserId) -> Result<(), Self::Error>;
}

/// Workspace role repository trait
#[async_trait]
pub trait WorkspaceRoleRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find role by ID
    async fn find_by_id(&self, id: RoleId) -> Result<Option<WorkspaceRole>, Self::Error>;

    /// Find all roles for a workspace
    async fn find_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<WorkspaceRole>, Self::Error>;

    /// Find default role for a workspace
    async fn find_default_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Option<WorkspaceRole>, Self::Error>;

    /// Save role
    async fn save(&self, role: &WorkspaceRole) -> Result<(), Self::Error>;

    /// Delete role
    async fn delete(&self, id: RoleId) -> Result<(), Self::Error>;

    /// Delete all roles for a workspace
    async fn delete_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<(), Self::Error>;
}

/// Workspace role permission repository trait
#[async_trait]
pub trait WorkspaceRolePermissionRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find all permissions for a role
    async fn find_by_role_id(
        &self,
        role_id: RoleId,
    ) -> Result<Vec<WorkspaceRolePermission>, Self::Error>;

    /// Find specific permission for a role
    async fn find_by_role_and_permission(
        &self,
        role_id: RoleId,
        permission: &Permission,
    ) -> Result<Option<WorkspaceRolePermission>, Self::Error>;

    /// Save permission
    async fn save(&self, permission: &WorkspaceRolePermission) -> Result<(), Self::Error>;

    /// Delete permission
    async fn delete(&self, role_id: RoleId, permission: &Permission) -> Result<(), Self::Error>;

    /// Delete all permissions for a role
    async fn delete_by_role_id(&self, role_id: RoleId) -> Result<(), Self::Error>;
}

/// Workspace invitation repository trait
#[async_trait]
pub trait WorkspaceInvitationRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find invitation by ID
    async fn find_by_id(
        &self,
        id: InvitationId,
    ) -> Result<Option<WorkspaceInvitation>, Self::Error>;

    /// Find invitation by token hash
    async fn find_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<WorkspaceInvitation>, Self::Error>;

    /// Find all invitations for a workspace
    async fn find_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<WorkspaceInvitation>, Self::Error>;

    /// Find invitation by workspace and email
    async fn find_by_workspace_and_email(
        &self,
        workspace_id: WorkspaceId,
        email: &str,
    ) -> Result<Option<WorkspaceInvitation>, Self::Error>;

    /// Save invitation
    async fn save(&self, invitation: &WorkspaceInvitation) -> Result<(), Self::Error>;

    /// Delete invitation
    async fn delete(&self, id: InvitationId) -> Result<(), Self::Error>;

    /// Delete all invitations for a workspace
    async fn delete_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<(), Self::Error>;

    /// Delete expired invitations
    async fn delete_expired(&self) -> Result<u64, Self::Error>;
}
