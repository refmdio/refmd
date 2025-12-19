use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::context::AppContext;
use crate::http::documents::DownloadFormat;
use application::core::services::errors::ServiceError;
use application::workspaces::ports::workspace_repository::{
    WorkspaceInvitationRecord, WorkspaceListItem, WorkspaceMemberDetail, WorkspaceRoleRecord,
};
use domain::access::permissions::PermissionOverride;
use domain::workspaces::roles::{WorkspaceBaseRole, WorkspaceRoleKind, WorkspaceSystemRole};

#[derive(Debug, Serialize, ToSchema)]
pub struct WorkspaceResponse {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub is_personal: bool,
    pub role_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_role_id: Option<Uuid>,
    pub is_default: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWorkspaceRequest {
    pub name: String,
    pub icon: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WorkspaceMemberResponse {
    pub workspace_id: Uuid,
    pub user_id: Uuid,
    pub email: String,
    pub name: String,
    pub role_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_role_id: Option<Uuid>,
    pub is_default: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateMemberRoleRequest {
    pub role_kind: String,
    pub system_role: Option<String>,
    pub custom_role_id: Option<Uuid>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct PermissionOverridePayload {
    pub permission: String,
    pub allowed: bool,
}

#[derive(Debug, Deserialize, ToSchema, Default)]
pub struct DownloadWorkspaceQuery {
    #[serde(default)]
    pub format: DownloadFormat,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WorkspaceRoleResponse {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub base_role: String,
    pub priority: i32,
    pub overrides: Vec<PermissionOverridePayload>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WorkspaceInvitationResponse {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub email: String,
    pub role_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_role_id: Option<Uuid>,
    pub invited_by: Uuid,
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_by: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWorkspaceRoleRequest {
    pub name: String,
    pub base_role: String,
    pub description: Option<String>,
    pub priority: Option<i32>,
    pub overrides: Option<Vec<PermissionOverridePayload>>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateWorkspaceRoleRequest {
    pub name: Option<String>,
    pub base_role: Option<String>,
    pub description: Option<String>,
    pub priority: Option<i32>,
    pub overrides: Option<Vec<PermissionOverridePayload>>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateWorkspaceRequest {
    pub name: Option<String>,
    pub icon: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SwitchWorkspaceResponse {
    pub access_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WorkspacePermissionsResponse {
    pub workspace_id: Uuid,
    pub permissions: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWorkspaceInvitationRequest {
    pub email: String,
    pub role_kind: String,
    pub system_role: Option<String>,
    pub custom_role_id: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

pub fn to_response(row: WorkspaceListItem) -> WorkspaceResponse {
    WorkspaceResponse {
        id: row.id,
        name: row.name,
        slug: row.slug,
        icon: row.icon,
        description: row.description,
        is_personal: row.is_personal,
        role_kind: row.role_kind.as_str().to_string(),
        system_role: row.system_role.map(|role| role.as_str().to_string()),
        custom_role_id: row.custom_role_id,
        is_default: row.is_default,
    }
}

pub fn map_service_error(err: ServiceError) -> crate::http::error::ApiError {
    crate::http::error::map_service_error(err, "workspace_service_error")
}

pub fn member_response_from(detail: WorkspaceMemberDetail) -> WorkspaceMemberResponse {
    WorkspaceMemberResponse {
        workspace_id: detail.workspace_id,
        user_id: detail.user_id,
        email: detail.user_email,
        name: detail.user_name,
        role_kind: detail.role_kind.as_str().to_string(),
        system_role: detail.system_role.map(|role| role.as_str().to_string()),
        custom_role_id: detail.custom_role_id,
        is_default: detail.is_default,
    }
}

pub fn role_response_from(record: WorkspaceRoleRecord) -> WorkspaceRoleResponse {
    WorkspaceRoleResponse {
        id: record.id,
        workspace_id: record.workspace_id,
        name: record.name,
        description: record.description,
        base_role: record.base_role.as_str().to_string(),
        priority: record.priority,
        overrides: record
            .overrides
            .into_iter()
            .map(|item| PermissionOverridePayload {
                permission: item.permission,
                allowed: item.allowed,
            })
            .collect(),
    }
}

pub fn invitation_response_from(record: WorkspaceInvitationRecord) -> WorkspaceInvitationResponse {
    WorkspaceInvitationResponse {
        id: record.id,
        workspace_id: record.workspace_id,
        email: record.email,
        role_kind: record.role_kind.as_str().to_string(),
        system_role: record.system_role.map(|role| role.as_str().to_string()),
        custom_role_id: record.custom_role_id,
        invited_by: record.invited_by,
        token: record.token,
        expires_at: record.expires_at,
        accepted_by: record.accepted_by,
        accepted_at: record.accepted_at,
        revoked_at: record.revoked_at,
        created_at: record.created_at,
    }
}

pub async fn require_permission(
    ctx: &AppContext,
    workspace_id: Uuid,
    user_id: Uuid,
    permission: &str,
) -> Result<(), crate::http::error::ApiError> {
    let set = ctx
        .workspace_service()
        .resolve_permission_set(workspace_id, user_id)
        .await
        .map_err(map_service_error)?
        .ok_or(crate::http::error::ApiError::forbidden("forbidden"))?;
    if set.allows(permission) {
        Ok(())
    } else {
        Err(crate::http::error::ApiError::forbidden("forbidden"))
    }
}

pub async fn require_any_permission(
    ctx: &AppContext,
    workspace_id: Uuid,
    user_id: Uuid,
    permissions: &[&str],
) -> Result<(), crate::http::error::ApiError> {
    if permissions.is_empty() {
        return Err(crate::http::error::ApiError::forbidden("forbidden"));
    }
    let set = ctx
        .workspace_service()
        .resolve_permission_set(workspace_id, user_id)
        .await
        .map_err(map_service_error)?
        .ok_or(crate::http::error::ApiError::forbidden("forbidden"))?;
    if permissions.iter().any(|perm| set.allows(perm)) {
        Ok(())
    } else {
        Err(crate::http::error::ApiError::forbidden("forbidden"))
    }
}

pub fn validate_base_role(role: &str) -> bool {
    WorkspaceBaseRole::parse(role).is_some()
}

pub fn parse_role_kind(role_kind: &str) -> Result<WorkspaceRoleKind, crate::http::error::ApiError> {
    WorkspaceRoleKind::parse(role_kind).ok_or(crate::http::error::ApiError::bad_request(
        "invalid_role_kind",
    ))
}

pub fn parse_system_role(
    role: Option<&str>,
) -> Result<Option<WorkspaceSystemRole>, crate::http::error::ApiError> {
    role.map(|value| {
        WorkspaceSystemRole::parse(value).ok_or(crate::http::error::ApiError::bad_request(
            "invalid_system_role",
        ))
    })
    .transpose()
}

pub fn parse_base_role(role: &str) -> Result<WorkspaceBaseRole, crate::http::error::ApiError> {
    WorkspaceBaseRole::parse(role).ok_or(crate::http::error::ApiError::bad_request(
        "invalid_base_role",
    ))
}

pub fn parse_optional_base_role(
    role: Option<&str>,
) -> Result<Option<WorkspaceBaseRole>, crate::http::error::ApiError> {
    role.map(parse_base_role).transpose()
}

pub fn normalize_overrides(
    overrides: Option<Vec<PermissionOverridePayload>>,
) -> Result<Vec<PermissionOverride>, crate::http::error::ApiError> {
    let mut out = Vec::new();
    if let Some(items) = overrides {
        for item in items {
            let perm = item.permission.trim();
            if perm.is_empty() {
                return Err(crate::http::error::ApiError::bad_request(
                    "invalid_permission_override",
                ));
            }
            out.push(PermissionOverride::new(perm.to_string(), item.allowed));
        }
    }
    Ok(out)
}
