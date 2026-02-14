//! Workspace repository traits

use async_trait::async_trait;

use super::member::WorkspaceMember;
use super::role::WorkspaceRole;
use super::value_objects::{RoleId, Slug, WorkspaceId};
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

    /// Find workspaces by a list of IDs (batch fetch)
    async fn find_by_ids(&self, ids: &[WorkspaceId]) -> Result<Vec<Workspace>, Self::Error>;

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

    /// Find roles by a list of IDs (batch fetch)
    async fn find_by_ids(&self, ids: &[RoleId]) -> Result<Vec<WorkspaceRole>, Self::Error>;

    /// Find all roles for a workspace
    async fn find_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<WorkspaceRole>, Self::Error>;

    /// Save role
    async fn save(&self, role: &WorkspaceRole) -> Result<(), Self::Error>;

    /// Delete role
    async fn delete(&self, id: RoleId) -> Result<(), Self::Error>;

    /// Delete all roles for a workspace
    async fn delete_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<(), Self::Error>;
}

