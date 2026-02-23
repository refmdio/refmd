//! Workspace repository traits

use async_trait::async_trait;

use super::invitation::WorkspaceInvitation;
use super::member::WorkspaceMember;
use super::role::WorkspaceRole;
use super::role_permission::WorkspaceRolePermission;
use super::value_objects::{InvitationId, RoleId, Slug, WorkspaceId};
use super::workspace::Workspace;
use crate::identity::UserId;

/// Classification helpers for workspace repository errors.
pub trait WorkspaceRepositoryErrorClassifier {
    /// Returns true if the error indicates a slug uniqueness conflict
    fn is_slug_conflict(&self) -> bool { false }
}

/// Workspace repository trait
#[async_trait]
pub trait WorkspaceRepository: Send + Sync {
    type Error: std::error::Error + WorkspaceRepositoryErrorClassifier + Send + Sync + 'static;

    /// Find workspace by ID
    async fn find_by_id(&self, id: WorkspaceId) -> Result<Option<Workspace>, Self::Error>;

    /// Find workspace by slug
    async fn find_by_slug(&self, slug: &Slug) -> Result<Option<Workspace>, Self::Error>;

    /// Find workspaces by a list of IDs (batch fetch)
    async fn find_by_ids(&self, ids: &[WorkspaceId]) -> Result<Vec<Workspace>, Self::Error>;

    /// Check if slug exists
    async fn slug_exists(&self, slug: &Slug) -> Result<bool, Self::Error>;

    /// Save workspace (UPSERT - use for creation)
    async fn save(&self, workspace: &Workspace) -> Result<(), Self::Error>;

    /// Update workspace (UPDATE only - returns false if not found)
    async fn update(&self, workspace: &Workspace) -> Result<bool, Self::Error>;

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

/// Classification helpers for role repository errors.
/// Implementations should return `true` for the appropriate variant
/// so the application layer can map infrastructure errors to domain-appropriate
/// status codes without inspecting error message strings.
pub trait WorkspaceRoleRepositoryErrorClassifier {
    /// Returns true if the error indicates the role is still in use by members (FK constraint)
    fn is_role_in_use(&self) -> bool { false }
    /// Returns true if the error indicates the role became the default concurrently
    fn is_role_became_default(&self) -> bool { false }
    /// Returns true if the error indicates the role was not found
    fn is_role_not_found(&self) -> bool { false }
}

/// Workspace role repository trait
#[async_trait]
pub trait WorkspaceRoleRepository: Send + Sync {
    type Error: std::error::Error + WorkspaceRoleRepositoryErrorClassifier + Send + Sync + 'static;

    /// Find role by ID
    async fn find_by_id(&self, id: RoleId) -> Result<Option<WorkspaceRole>, Self::Error>;

    /// Find roles by a list of IDs (batch fetch)
    async fn find_by_ids(&self, ids: &[RoleId]) -> Result<Vec<WorkspaceRole>, Self::Error>;

    /// Find all roles for a workspace
    async fn find_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<WorkspaceRole>, Self::Error>;

    /// Save role (UPSERT - use for creation)
    async fn save(&self, role: &WorkspaceRole) -> Result<(), Self::Error>;

    /// Update role (UPDATE only - returns false if not found)
    async fn update(&self, role: &WorkspaceRole) -> Result<bool, Self::Error>;

    /// Delete role (workspace_id for defense-in-depth scoping)
    async fn delete(&self, id: RoleId, workspace_id: WorkspaceId) -> Result<(), Self::Error>;

    /// Delete all roles for a workspace
    async fn delete_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<(), Self::Error>;

    /// Atomically swap the default role for a workspace.
    /// Sets old default to is_default=false and target to is_default=true in one transaction.
    /// If `new_name` is provided, also updates the target role's name in the same transaction.
    async fn swap_default(
        &self,
        workspace_id: WorkspaceId,
        new_default_role_id: RoleId,
        new_name: Option<&str>,
    ) -> Result<(), Self::Error>;

    /// Atomically create a role and set it as default in one transaction.
    async fn save_and_set_default(&self, role: &WorkspaceRole) -> Result<(), Self::Error>;
}

/// Workspace role permission repository trait
#[async_trait]
pub trait WorkspaceRolePermissionRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find all permission overrides for a role
    async fn find_by_role_id(
        &self,
        role_id: RoleId,
    ) -> Result<Vec<WorkspaceRolePermission>, Self::Error>;

    /// Find all permission overrides for multiple roles (batch fetch)
    async fn find_by_role_ids(
        &self,
        role_ids: &[RoleId],
    ) -> Result<Vec<WorkspaceRolePermission>, Self::Error>;

    /// Save permission overrides for a role (replaces existing)
    async fn save_batch(
        &self,
        role_id: RoleId,
        perms: &[(String, bool)],
    ) -> Result<(), Self::Error>;

    /// Delete all permission overrides for a role
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

    /// Find active (non-revoked, non-expired) invitations for a workspace
    async fn find_active_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<WorkspaceInvitation>, Self::Error>;

    /// Save a new invitation
    async fn save(&self, invitation: &WorkspaceInvitation) -> Result<(), Self::Error>;

    /// Atomically revoke an invitation (set revoked_at) where it belongs to the
    /// given workspace and is not already revoked. Returns `true` if a row was
    /// updated, `false` if the invitation was not found or already revoked.
    async fn revoke(
        &self,
        id: InvitationId,
        workspace_id: WorkspaceId,
    ) -> Result<bool, Self::Error>;

    /// Count all invitations that reference a specific role_id.
    /// Used to report invalidated_invitation_count when deleting a role.
    /// Counts ALL rows (not just active) because FK cascade `ON DELETE SET NULL`
    /// affects every row with this role_id.
    async fn count_by_role_id(
        &self,
        workspace_id: WorkspaceId,
        role_id: RoleId,
    ) -> Result<i64, Self::Error>;

    /// Revoke all active (non-revoked) invitations for a workspace.
    /// Used during KEK rotation to invalidate invitations carrying stale keys.
    /// Returns the number of revoked invitations.
    async fn revoke_all_active(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<i64, Self::Error>;
}

