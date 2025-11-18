use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct WorkspaceRow {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub icon: Option<String>,
    pub description: Option<String>,
    pub is_personal: bool,
}

#[derive(Debug, Clone)]
pub struct WorkspaceListItem {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub icon: Option<String>,
    pub description: Option<String>,
    pub is_personal: bool,
    pub role_kind: String,
    pub system_role: Option<String>,
    pub custom_role_id: Option<Uuid>,
    pub is_default: bool,
}

#[derive(Debug, Clone)]
pub struct WorkspaceMemberRow {
    pub workspace_id: Uuid,
    pub user_id: Uuid,
    pub role_kind: String,
    pub system_role: Option<String>,
    pub custom_role_id: Option<Uuid>,
    pub is_default: bool,
}

#[derive(Debug, Clone)]
pub struct WorkspaceMemberDetail {
    pub workspace_id: Uuid,
    pub user_id: Uuid,
    pub role_kind: String,
    pub system_role: Option<String>,
    pub custom_role_id: Option<Uuid>,
    pub is_default: bool,
    pub user_email: String,
    pub user_name: String,
}

#[derive(Debug, Clone)]
pub struct WorkspacePermissionRecord {
    pub workspace_id: Uuid,
    pub user_id: Uuid,
    pub role_kind: String,
    pub system_role: Option<String>,
    pub custom_role_id: Option<Uuid>,
    pub custom_base_role: Option<String>,
    pub overrides: Vec<(String, bool)>,
}

#[derive(Debug, Clone)]
pub struct WorkspaceRoleRecord {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub base_role: String,
    pub priority: i32,
    pub overrides: Vec<(String, bool)>,
}

#[derive(Debug, Clone)]
pub struct WorkspaceInvitationRecord {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub email: String,
    pub role_kind: String,
    pub system_role: Option<String>,
    pub custom_role_id: Option<Uuid>,
    pub invited_by: Uuid,
    pub token: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub accepted_by: Option<Uuid>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[async_trait]
pub trait WorkspaceRepository: Send + Sync {
    async fn list_for_user(&self, user_id: Uuid) -> anyhow::Result<Vec<WorkspaceListItem>>;
    async fn create_workspace(
        &self,
        creator_id: Uuid,
        name: &str,
        slug: &str,
        icon: Option<&str>,
        description: Option<&str>,
        is_personal: bool,
    ) -> anyhow::Result<WorkspaceRow>;
    async fn get_workspace(&self, workspace_id: Uuid) -> anyhow::Result<Option<WorkspaceRow>>;
    async fn create_workspace_with_id(
        &self,
        workspace_id: Uuid,
        created_by: Option<Uuid>,
        name: &str,
        slug: &str,
        icon: Option<&str>,
        description: Option<&str>,
        is_personal: bool,
    ) -> anyhow::Result<WorkspaceRow>;
    async fn add_member(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        role_kind: &str,
        system_role: Option<&str>,
        custom_role_id: Option<Uuid>,
    ) -> anyhow::Result<WorkspaceMemberRow>;
    async fn set_default_workspace(
        &self,
        user_id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<WorkspaceMemberRow>;

    async fn list_members(&self, workspace_id: Uuid) -> anyhow::Result<Vec<WorkspaceMemberDetail>>;

    async fn get_member_detail(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> anyhow::Result<Option<WorkspaceMemberDetail>>;

    async fn update_member_role(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        role_kind: &str,
        system_role: Option<&str>,
        custom_role_id: Option<Uuid>,
    ) -> anyhow::Result<WorkspaceMemberRow>;

    async fn get_member_with_permissions(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> anyhow::Result<Option<WorkspacePermissionRecord>>;

    async fn list_roles(&self, workspace_id: Uuid) -> anyhow::Result<Vec<WorkspaceRoleRecord>>;

    async fn create_role(
        &self,
        workspace_id: Uuid,
        name: &str,
        base_role: &str,
        description: Option<&str>,
        priority: i32,
        overrides: &[(String, bool)],
    ) -> anyhow::Result<WorkspaceRoleRecord>;

    async fn update_role(
        &self,
        workspace_id: Uuid,
        role_id: Uuid,
        name: Option<&str>,
        base_role: Option<&str>,
        description: Option<&str>,
        priority: Option<i32>,
        overrides: Option<&[(String, bool)]>,
    ) -> anyhow::Result<WorkspaceRoleRecord>;

    async fn delete_role(&self, workspace_id: Uuid, role_id: Uuid) -> anyhow::Result<bool>;
    async fn delete_workspace(&self, workspace_id: Uuid) -> anyhow::Result<bool>;

    async fn delete_member(&self, workspace_id: Uuid, user_id: Uuid) -> anyhow::Result<bool>;
    async fn update_workspace(
        &self,
        workspace_id: Uuid,
        name: Option<&str>,
        icon: Option<&str>,
        description: Option<&str>,
    ) -> anyhow::Result<Option<WorkspaceRow>>;

    async fn create_invitation(
        &self,
        workspace_id: Uuid,
        email: &str,
        role_kind: &str,
        system_role: Option<&str>,
        custom_role_id: Option<Uuid>,
        invited_by: Uuid,
        token: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> anyhow::Result<WorkspaceInvitationRecord>;

    async fn list_invitations(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<Vec<WorkspaceInvitationRecord>>;

    async fn accept_invitation(
        &self,
        token: &str,
        user_id: Uuid,
        user_email: &str,
    ) -> anyhow::Result<WorkspaceInvitationRecord>;

    async fn revoke_invitation(
        &self,
        workspace_id: Uuid,
        invitation_id: Uuid,
    ) -> anyhow::Result<Option<WorkspaceInvitationRecord>>;
}
