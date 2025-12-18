use anyhow::bail;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use application::workspaces::ports::workspace_repository::{
    WorkspaceInvitationRecord, WorkspaceListItem, WorkspaceMemberDetail, WorkspaceMemberRow,
    WorkspacePermissionRecord, WorkspaceRepository, WorkspaceRoleRecord, WorkspaceRow,
    WorkspaceSetDefaultError,
};
use domain::access::permissions::PermissionOverride;
use domain::workspaces::roles::{WorkspaceBaseRole, WorkspaceRoleKind, WorkspaceSystemRole};

use super::SqlxWorkspaceRepository;

mod invitations;
mod members;
mod roles;
mod workspaces;

#[async_trait]
impl WorkspaceRepository for SqlxWorkspaceRepository {
    async fn list_for_user(&self, user_id: Uuid) -> anyhow::Result<Vec<WorkspaceListItem>> {
        self.list_for_user_impl(user_id).await
    }

    async fn create_workspace(
        &self,
        creator_id: Uuid,
        name: &str,
        slug: &str,
        icon: Option<&str>,
        description: Option<&str>,
        is_personal: bool,
    ) -> anyhow::Result<WorkspaceRow> {
        self.create_workspace_impl(creator_id, name, slug, icon, description, is_personal)
            .await
    }

    async fn get_workspace(&self, workspace_id: Uuid) -> anyhow::Result<Option<WorkspaceRow>> {
        self.get_workspace_impl(workspace_id).await
    }

    async fn create_workspace_with_id(
        &self,
        workspace_id: Uuid,
        created_by: Option<Uuid>,
        name: &str,
        slug: &str,
        icon: Option<&str>,
        description: Option<&str>,
        is_personal: bool,
    ) -> anyhow::Result<WorkspaceRow> {
        self.create_workspace_with_id_impl(
            workspace_id,
            created_by,
            name,
            slug,
            icon,
            description,
            is_personal,
        )
        .await
    }

    async fn add_member(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        role_kind: WorkspaceRoleKind,
        system_role: Option<WorkspaceSystemRole>,
        custom_role_id: Option<Uuid>,
    ) -> anyhow::Result<WorkspaceMemberRow> {
        self.add_member_impl(
            workspace_id,
            user_id,
            role_kind,
            system_role,
            custom_role_id,
        )
        .await
    }

    async fn set_default_workspace(
        &self,
        user_id: Uuid,
        workspace_id: Uuid,
    ) -> Result<WorkspaceMemberRow, WorkspaceSetDefaultError> {
        self.set_default_workspace_impl(user_id, workspace_id).await
    }

    async fn list_members(&self, workspace_id: Uuid) -> anyhow::Result<Vec<WorkspaceMemberDetail>> {
        self.list_members_impl(workspace_id).await
    }

    async fn get_member_detail(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> anyhow::Result<Option<WorkspaceMemberDetail>> {
        self.get_member_detail_impl(workspace_id, user_id).await
    }

    async fn update_member_role(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        role_kind: WorkspaceRoleKind,
        system_role: Option<WorkspaceSystemRole>,
        custom_role_id: Option<Uuid>,
    ) -> anyhow::Result<WorkspaceMemberRow> {
        self.update_member_role_impl(
            workspace_id,
            user_id,
            role_kind,
            system_role,
            custom_role_id,
        )
        .await
    }

    async fn get_member_with_permissions(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> anyhow::Result<Option<WorkspacePermissionRecord>> {
        self.get_member_with_permissions_impl(workspace_id, user_id)
            .await
    }

    async fn count_system_role_members(
        &self,
        workspace_id: Uuid,
        system_role: WorkspaceSystemRole,
    ) -> anyhow::Result<i64> {
        self.count_system_role_members_impl(workspace_id, system_role)
            .await
    }

    async fn list_roles(&self, workspace_id: Uuid) -> anyhow::Result<Vec<WorkspaceRoleRecord>> {
        self.list_roles_impl(workspace_id).await
    }

    async fn create_role(
        &self,
        workspace_id: Uuid,
        name: &str,
        base_role: WorkspaceBaseRole,
        description: Option<&str>,
        priority: i32,
        overrides: &[PermissionOverride],
    ) -> anyhow::Result<WorkspaceRoleRecord> {
        self.create_role_impl(
            workspace_id,
            name,
            base_role,
            description,
            priority,
            overrides,
        )
        .await
    }

    async fn update_role(
        &self,
        workspace_id: Uuid,
        role_id: Uuid,
        name: Option<&str>,
        base_role: Option<WorkspaceBaseRole>,
        description: Option<&str>,
        priority: Option<i32>,
        overrides: Option<&[PermissionOverride]>,
    ) -> anyhow::Result<WorkspaceRoleRecord> {
        self.update_role_impl(
            workspace_id,
            role_id,
            name,
            base_role,
            description,
            priority,
            overrides,
        )
        .await
    }

    async fn delete_role(&self, workspace_id: Uuid, role_id: Uuid) -> anyhow::Result<bool> {
        self.delete_role_impl(workspace_id, role_id).await
    }

    async fn delete_workspace(&self, workspace_id: Uuid) -> anyhow::Result<bool> {
        self.delete_workspace_impl(workspace_id).await
    }

    async fn get_role(
        &self,
        workspace_id: Uuid,
        role_id: Uuid,
    ) -> anyhow::Result<Option<WorkspaceRoleRecord>> {
        self.get_role_impl(workspace_id, role_id).await
    }

    async fn delete_member(&self, workspace_id: Uuid, user_id: Uuid) -> anyhow::Result<bool> {
        self.delete_member_impl(workspace_id, user_id).await
    }

    async fn update_workspace(
        &self,
        workspace_id: Uuid,
        name: Option<&str>,
        icon: Option<&str>,
        description: Option<&str>,
    ) -> anyhow::Result<Option<WorkspaceRow>> {
        self.update_workspace_impl(workspace_id, name, icon, description)
            .await
    }

    async fn create_invitation(
        &self,
        workspace_id: Uuid,
        email: &str,
        role_kind: WorkspaceRoleKind,
        system_role: Option<WorkspaceSystemRole>,
        custom_role_id: Option<Uuid>,
        invited_by: Uuid,
        token: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> anyhow::Result<WorkspaceInvitationRecord> {
        self.create_invitation_impl(
            workspace_id,
            email,
            role_kind,
            system_role,
            custom_role_id,
            invited_by,
            token,
            expires_at,
        )
        .await
    }

    async fn list_invitations(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<Vec<WorkspaceInvitationRecord>> {
        self.list_invitations_impl(workspace_id).await
    }

    async fn accept_invitation(
        &self,
        token: &str,
        user_id: Uuid,
        email: &str,
    ) -> anyhow::Result<WorkspaceInvitationRecord> {
        self.accept_invitation_impl(token, user_id, email).await
    }

    async fn revoke_invitation(
        &self,
        workspace_id: Uuid,
        invitation_id: Uuid,
    ) -> anyhow::Result<Option<WorkspaceInvitationRecord>> {
        self.revoke_invitation_impl(workspace_id, invitation_id)
            .await
    }

    async fn list_all_workspace_ids(&self) -> anyhow::Result<Vec<Uuid>> {
        self.list_all_workspace_ids_impl().await
    }
}
