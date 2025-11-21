use axum::routing::{delete, get, patch, post};
use axum::{
    Json, Router,
    response::{IntoResponse, Response},
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::application::access;
use crate::application::ports::workspace_repository::{
    WorkspaceInvitationRecord, WorkspaceListItem, WorkspaceMemberDetail, WorkspaceRoleRecord,
};
use crate::application::services::auth::user_sessions::SessionMetadata;
use crate::application::services::errors::ServiceError;
use crate::domain::workspaces::permissions::{
    PERM_DOC_VIEW, PERM_MEMBER_INVITE, PERM_MEMBER_REMOVE, PERM_MEMBER_UPDATE_ROLE,
    PERM_MEMBER_VIEW, PERM_WORKSPACE_DELETE, PERM_WORKSPACE_UPDATE,
};
use crate::presentation::context::AppContext;
use crate::presentation::http::auth::{
    self, Bearer, apply_session_cookies, extract_client_ip, extract_refresh_token,
    extract_user_agent,
};
#[allow(unused_imports)]
use crate::presentation::http::documents::DocumentDownloadBinary;
use crate::presentation::http::documents::DownloadFormat;

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/workspaces", get(list_workspaces).post(create_workspace))
        .route(
            "/workspaces/:id",
            get(get_workspace_detail)
                .put(update_workspace)
                .delete(delete_workspace),
        )
        .route("/workspaces/:id/leave", post(leave_workspace))
        .route("/workspaces/:id/switch", post(switch_workspace))
        .route("/workspaces/:id/members", get(list_members))
        .route(
            "/workspaces/:id/members/:user_id",
            patch(update_member_role).delete(remove_member),
        )
        .route(
            "/workspaces/:id/permissions",
            get(get_workspace_permissions),
        )
        .route("/workspaces/:id/roles", get(list_roles).post(create_role))
        .route(
            "/workspaces/:id/roles/:role_id",
            patch(update_role).delete(delete_role),
        )
        .route(
            "/workspaces/:id/invitations",
            get(list_invitations).post(create_invitation),
        )
        .route(
            "/workspaces/:id/invitations/:invitation_id",
            delete(revoke_invitation),
        )
        .route("/workspaces/:id/download", get(download_workspace_archive))
        .route(
            "/workspace-invitations/:token/accept",
            post(accept_invitation),
        )
        .with_state(ctx)
}

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

fn to_response(
    row: crate::application::ports::workspace_repository::WorkspaceListItem,
) -> WorkspaceResponse {
    WorkspaceResponse {
        id: row.id,
        name: row.name,
        slug: row.slug,
        icon: row.icon,
        description: row.description,
        is_personal: row.is_personal,
        role_kind: row.role_kind,
        system_role: row.system_role,
        custom_role_id: row.custom_role_id,
        is_default: row.is_default,
    }
}

pub(crate) fn map_service_error(err: ServiceError) -> StatusCode {
    match err {
        ServiceError::Unauthorized | ServiceError::TokenExpired => StatusCode::UNAUTHORIZED,
        ServiceError::Forbidden => StatusCode::FORBIDDEN,
        ServiceError::Conflict => StatusCode::CONFLICT,
        ServiceError::NotFound => StatusCode::NOT_FOUND,
        ServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
        ServiceError::Unexpected(inner) => {
            tracing::error!(error = ?inner, "workspace_service_error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

fn member_response_from(detail: WorkspaceMemberDetail) -> WorkspaceMemberResponse {
    WorkspaceMemberResponse {
        workspace_id: detail.workspace_id,
        user_id: detail.user_id,
        email: detail.user_email,
        name: detail.user_name,
        role_kind: detail.role_kind,
        system_role: detail.system_role,
        custom_role_id: detail.custom_role_id,
        is_default: detail.is_default,
    }
}

fn role_response_from(record: WorkspaceRoleRecord) -> WorkspaceRoleResponse {
    WorkspaceRoleResponse {
        id: record.id,
        workspace_id: record.workspace_id,
        name: record.name,
        description: record.description,
        base_role: record.base_role,
        priority: record.priority,
        overrides: record
            .overrides
            .into_iter()
            .map(|(permission, allowed)| PermissionOverridePayload {
                permission,
                allowed,
            })
            .collect(),
    }
}

fn invitation_response_from(record: WorkspaceInvitationRecord) -> WorkspaceInvitationResponse {
    WorkspaceInvitationResponse {
        id: record.id,
        workspace_id: record.workspace_id,
        email: record.email,
        role_kind: record.role_kind,
        system_role: record.system_role,
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

async fn require_permission(
    ctx: &AppContext,
    workspace_id: Uuid,
    user_id: Uuid,
    permission: &str,
) -> Result<(), StatusCode> {
    let set = ctx
        .workspace_service()
        .resolve_permission_set(workspace_id, user_id)
        .await
        .map_err(map_service_error)?
        .ok_or(StatusCode::FORBIDDEN)?;
    if set.allows(permission) {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

async fn require_any_permission(
    ctx: &AppContext,
    workspace_id: Uuid,
    user_id: Uuid,
    permissions: &[&str],
) -> Result<(), StatusCode> {
    if permissions.is_empty() {
        return Err(StatusCode::FORBIDDEN);
    }
    let set = ctx
        .workspace_service()
        .resolve_permission_set(workspace_id, user_id)
        .await
        .map_err(map_service_error)?
        .ok_or(StatusCode::FORBIDDEN)?;
    if permissions.iter().any(|perm| set.allows(perm)) {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn validate_base_role(role: &str) -> bool {
    matches!(role, "viewer" | "editor" | "admin")
}

fn normalize_overrides(
    overrides: Option<Vec<PermissionOverridePayload>>,
) -> Result<Vec<(String, bool)>, StatusCode> {
    let mut out = Vec::new();
    if let Some(items) = overrides {
        for item in items {
            let perm = item.permission.trim();
            if perm.is_empty() {
                return Err(StatusCode::BAD_REQUEST);
            }
            out.push((perm.to_string(), item.allowed));
        }
    }
    Ok(out)
}

#[utoipa::path(get, path = "/api/workspaces", tag = "Workspaces", responses((status = 200, body = [WorkspaceResponse])))]
pub async fn list_workspaces(
    State(ctx): State<AppContext>,
    bearer: Bearer,
) -> Result<Json<Vec<WorkspaceResponse>>, StatusCode> {
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let items = ctx
        .workspace_service()
        .list_for_user(user_id)
        .await
        .map_err(map_service_error)?
        .into_iter()
        .map(to_response)
        .collect();
    Ok(Json(items))
}

#[utoipa::path(
    get,
    path = "/api/workspaces/{id}/members",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    responses((status = 200, body = [WorkspaceMemberResponse]))
)]
pub async fn list_members(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<WorkspaceMemberResponse>>, StatusCode> {
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_permission(&ctx, id, user_id, PERM_MEMBER_VIEW).await?;
    let members = ctx
        .workspace_service()
        .list_members(id)
        .await
        .map_err(map_service_error)?
        .into_iter()
        .map(member_response_from)
        .collect();
    Ok(Json(members))
}

#[utoipa::path(
    get,
    path = "/api/workspaces/{id}/roles",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    responses((status = 200, body = [WorkspaceRoleResponse]))
)]
pub async fn list_roles(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<WorkspaceRoleResponse>>, StatusCode> {
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_any_permission(
        &ctx,
        id,
        user_id,
        &[
            PERM_MEMBER_VIEW,
            PERM_MEMBER_UPDATE_ROLE,
            PERM_MEMBER_INVITE,
        ],
    )
    .await?;
    let roles = ctx
        .workspace_service()
        .list_roles(id)
        .await
        .map_err(map_service_error)?
        .into_iter()
        .map(role_response_from)
        .collect();
    Ok(Json(roles))
}

#[utoipa::path(
    get,
    path = "/api/workspaces/{id}/invitations",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    responses((status = 200, body = [WorkspaceInvitationResponse]))
)]
pub async fn list_invitations(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<WorkspaceInvitationResponse>>, StatusCode> {
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_permission(&ctx, id, user_id, PERM_MEMBER_INVITE).await?;
    let invitations = ctx
        .workspace_service()
        .list_invitations(id)
        .await
        .map_err(map_service_error)?
        .into_iter()
        .map(invitation_response_from)
        .collect();
    Ok(Json(invitations))
}

#[utoipa::path(
    post,
    path = "/api/workspaces/{id}/invitations",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    request_body = CreateWorkspaceInvitationRequest,
    responses((status = 200, body = WorkspaceInvitationResponse))
)]
pub async fn create_invitation(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
    Json(body): Json<CreateWorkspaceInvitationRequest>,
) -> Result<Json<WorkspaceInvitationResponse>, StatusCode> {
    if body.email.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_permission(&ctx, id, user_id, PERM_MEMBER_INVITE).await?;
    let record = ctx
        .workspace_service()
        .create_invitation(
            id,
            user_id,
            &body.email,
            body.role_kind.as_str(),
            body.system_role.as_deref(),
            body.custom_role_id,
            body.expires_at,
        )
        .await
        .map_err(map_service_error)?;
    Ok(Json(invitation_response_from(record)))
}

#[utoipa::path(
    delete,
    path = "/api/workspaces/{id}/invitations/{invitation_id}",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace ID"),
        ("invitation_id" = Uuid, Path, description = "Invitation ID"),
    ),
    responses((status = 200, body = WorkspaceInvitationResponse))
)]
pub async fn revoke_invitation(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path((workspace_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<WorkspaceInvitationResponse>, StatusCode> {
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_permission(&ctx, workspace_id, user_id, PERM_MEMBER_INVITE).await?;
    let record = ctx
        .workspace_service()
        .revoke_invitation(workspace_id, invitation_id)
        .await
        .map_err(map_service_error)?;
    Ok(Json(invitation_response_from(record)))
}

#[utoipa::path(
    get,
    path = "/api/workspaces/{id}/download",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace ID"),
        ("format" = Option<DownloadFormat>, Query, description = "Download format (archive only)")
    ),
    responses(
        (status = 200, description = "Workspace download", body = DocumentDownloadBinary, content_type = "application/octet-stream"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Workspace not found")
    )
)]
pub async fn download_workspace_archive(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
    Query(params): Query<DownloadWorkspaceQuery>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    let error_response = |status: StatusCode, code: &str, message: String| {
        (
            status,
            Json(json!({
                "error": code,
                "message": message,
            })),
        )
    };

    let sub = auth::validate_bearer(&ctx, bearer)
        .await
        .map_err(|status| error_response(status, "unauthorized", "Unauthorized".to_string()))?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Unauthorized".to_string(),
        )
    })?;

    require_permission(&ctx, id, user_id, PERM_DOC_VIEW)
        .await
        .map_err(|status| error_response(status, "forbidden", "Forbidden".to_string()))?;

    let workspace = ctx
        .workspace_service()
        .get_workspace(id)
        .await
        .map_err(|err| {
            let status = map_service_error(err);
            let (code, message) = if status == StatusCode::NOT_FOUND {
                ("not_found", "Workspace not found".to_string())
            } else {
                ("internal", "Failed to load workspace".to_string())
            };
            error_response(status, code, message)
        })?
        .ok_or_else(|| {
            error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "Workspace not found".to_string(),
            )
        })?;

    let actor = access::Actor::User(user_id);
    let download = ctx
        .document_service()
        .download_workspace_root(&actor, id, &workspace.name, params.format.into())
        .await
        .map_err(|err| match err {
            ServiceError::Unauthorized | ServiceError::TokenExpired | ServiceError::Forbidden => {
                error_response(StatusCode::FORBIDDEN, "forbidden", "Forbidden".to_string())
            }
            ServiceError::Conflict | ServiceError::NotFound => error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "Workspace not found".to_string(),
            ),
            ServiceError::BadRequest(_) => error_response(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "Invalid download request".to_string(),
            ),
            ServiceError::Unexpected(inner) => {
                tracing::error!(error = ?inner, workspace_id = %id, "workspace_download_failed");
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "Failed to prepare download".to_string(),
                )
            }
        })?;

    let mut headers = HeaderMap::new();
    let content_type = HeaderValue::from_str(&download.content_type).map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_header",
            "Failed to prepare download headers".to_string(),
        )
    })?;
    headers.insert(axum::http::header::CONTENT_TYPE, content_type);
    headers.insert(
        axum::http::header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    let disposition = format!("attachment; filename=\"{}\"", download.filename);
    let content_disposition = HeaderValue::from_str(&disposition).map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_header",
            "Failed to prepare download headers".to_string(),
        )
    })?;
    headers.insert(axum::http::header::CONTENT_DISPOSITION, content_disposition);

    Ok((headers, download.bytes).into_response())
}

#[utoipa::path(
    post,
    path = "/api/workspaces/{id}/roles",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    request_body = CreateWorkspaceRoleRequest,
    responses((status = 200, body = WorkspaceRoleResponse))
)]
pub async fn create_role(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
    Json(body): Json<CreateWorkspaceRoleRequest>,
) -> Result<Json<WorkspaceRoleResponse>, StatusCode> {
    if body.name.trim().is_empty() || !validate_base_role(body.base_role.as_str()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let overrides = normalize_overrides(body.overrides)?;
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_permission(&ctx, id, user_id, PERM_MEMBER_UPDATE_ROLE).await?;
    let record = ctx
        .workspace_service()
        .create_role(
            id,
            user_id,
            body.name.trim(),
            body.base_role.trim(),
            body.description.as_deref(),
            body.priority.unwrap_or(0),
            &overrides,
        )
        .await
        .map_err(map_service_error)?;
    Ok(Json(role_response_from(record)))
}

#[utoipa::path(
    patch,
    path = "/api/workspaces/{id}/roles/{role_id}",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace ID"),
        ("role_id" = Uuid, Path, description = "Role ID"),
    ),
    request_body = UpdateWorkspaceRoleRequest,
    responses((status = 200, body = WorkspaceRoleResponse))
)]
pub async fn update_role(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path((workspace_id, role_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateWorkspaceRoleRequest>,
) -> Result<Json<WorkspaceRoleResponse>, StatusCode> {
    if let Some(base) = body.base_role.as_deref() {
        if !validate_base_role(base) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let overrides_vec = normalize_overrides(body.overrides.clone())?;
    let overrides_opt = if body.overrides.is_some() {
        Some(overrides_vec.as_slice())
    } else {
        None
    };
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_permission(&ctx, workspace_id, user_id, PERM_MEMBER_UPDATE_ROLE).await?;
    let mut record = ctx
        .workspace_service()
        .update_role(
            workspace_id,
            user_id,
            role_id,
            body.name.as_deref(),
            body.base_role.as_deref(),
            body.description.as_deref(),
            body.priority,
            overrides_opt,
        )
        .await
        .map_err(map_service_error)?;
    if body.overrides.is_some() {
        record.overrides = overrides_vec;
    }
    Ok(Json(role_response_from(record)))
}

#[utoipa::path(
    delete,
    path = "/api/workspaces/{id}/roles/{role_id}",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace ID"),
        ("role_id" = Uuid, Path, description = "Role ID"),
    ),
    responses((status = 204))
)]
pub async fn delete_role(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path((workspace_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, StatusCode> {
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_permission(&ctx, workspace_id, user_id, PERM_MEMBER_UPDATE_ROLE).await?;
    ctx.workspace_service()
        .delete_role(workspace_id, role_id)
        .await
        .map_err(map_service_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/api/workspaces", tag = "Workspaces", request_body = CreateWorkspaceRequest, responses((status = 200, body = WorkspaceResponse)))]
pub async fn create_workspace(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Json(payload): Json<CreateWorkspaceRequest>,
) -> Result<Json<WorkspaceResponse>, StatusCode> {
    if payload.name.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace = ctx
        .workspace_service()
        .create_workspace(
            user_id,
            payload.name.trim(),
            payload.icon.as_deref(),
            payload.description.as_deref(),
        )
        .await
        .map_err(map_service_error)?;
    let memberships = ctx
        .workspace_service()
        .list_for_user(user_id)
        .await
        .map_err(map_service_error)?;
    let created = memberships
        .into_iter()
        .find(|item| item.id == workspace.id)
        .unwrap_or(WorkspaceListItem {
            id: workspace.id,
            name: workspace.name,
            slug: workspace.slug,
            icon: workspace.icon,
            description: workspace.description,
            is_personal: workspace.is_personal,
            role_kind: "system".to_string(),
            system_role: Some("owner".to_string()),
            custom_role_id: None,
            is_default: false,
        });
    Ok(Json(to_response(created)))
}

#[utoipa::path(
    get,
    path = "/api/workspaces/{id}",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    responses((status = 200, body = WorkspaceResponse))
)]
pub async fn get_workspace_detail(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
) -> Result<Json<WorkspaceResponse>, StatusCode> {
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspaces = ctx
        .workspace_service()
        .list_for_user(user_id)
        .await
        .map_err(map_service_error)?;
    let workspace = workspaces
        .into_iter()
        .find(|ws| ws.id == id)
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(to_response(workspace)))
}

#[utoipa::path(
    put,
    path = "/api/workspaces/{id}",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    request_body = UpdateWorkspaceRequest,
    responses((status = 200, body = WorkspaceResponse))
)]
pub async fn update_workspace(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateWorkspaceRequest>,
) -> Result<Json<WorkspaceResponse>, StatusCode> {
    if let Some(name) = payload.name.as_deref() {
        if name.trim().is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_permission(&ctx, id, user_id, PERM_WORKSPACE_UPDATE).await?;
    let normalized_name = payload
        .name
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    let normalized_icon = payload
        .icon
        .as_ref()
        .map(|value| value.trim())
        .map(|value| value.to_string());
    let normalized_description = payload
        .description
        .as_ref()
        .map(|value| value.trim())
        .map(|value| value.to_string());
    let updated = ctx
        .workspace_service()
        .update_workspace(
            id,
            normalized_name.as_deref(),
            normalized_icon.as_deref(),
            normalized_description.as_deref(),
        )
        .await
        .map_err(map_service_error)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Refresh membership info to include role and default flags
    let memberships = ctx
        .workspace_service()
        .list_for_user(user_id)
        .await
        .map_err(map_service_error)?;
    let mut membership = memberships
        .into_iter()
        .find(|ws| ws.id == id)
        .ok_or(StatusCode::FORBIDDEN)?;
    membership.name = updated.name;
    membership.icon = updated.icon;
    membership.description = updated.description;
    membership.slug = updated.slug;
    Ok(Json(to_response(membership)))
}

#[utoipa::path(
    delete,
    path = "/api/workspaces/{id}",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    responses((status = 204))
)]
pub async fn delete_workspace(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_permission(&ctx, id, user_id, PERM_WORKSPACE_DELETE).await?;
    let workspace = ctx
        .workspace_service()
        .get_workspace(id)
        .await
        .map_err(map_service_error)?
        .ok_or(StatusCode::NOT_FOUND)?;
    if workspace.is_personal {
        return Err(StatusCode::BAD_REQUEST);
    }
    let members = ctx
        .workspace_service()
        .list_members(id)
        .await
        .map_err(map_service_error)?;
    if members.iter().any(|member| member.is_default) {
        return Err(StatusCode::CONFLICT);
    }
    ctx.workspace_service()
        .delete_workspace(id)
        .await
        .map_err(map_service_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    patch,
    path = "/api/workspaces/{id}/members/{user_id}",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace ID"),
        ("user_id" = Uuid, Path, description = "Target user ID"),
    ),
    request_body = UpdateMemberRoleRequest,
    responses((status = 200, body = WorkspaceMemberResponse))
)]
pub async fn update_member_role(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path((workspace_id, member_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateMemberRoleRequest>,
) -> Result<Json<WorkspaceMemberResponse>, StatusCode> {
    if body.role_kind != "system" && body.role_kind != "custom" {
        return Err(StatusCode::BAD_REQUEST);
    }
    if body.role_kind == "system" {
        match body.system_role.as_deref() {
            Some("owner" | "admin" | "editor" | "viewer") => {}
            _ => return Err(StatusCode::BAD_REQUEST),
        }
    }
    if body.role_kind == "custom" && body.custom_role_id.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_permission(&ctx, workspace_id, user_id, PERM_MEMBER_UPDATE_ROLE).await?;

    ctx.workspace_service()
        .update_member_role(
            workspace_id,
            member_id,
            user_id,
            &body.role_kind,
            body.system_role.as_deref(),
            body.custom_role_id,
        )
        .await
        .map_err(map_service_error)?;

    let updated = ctx
        .workspace_service()
        .list_members(workspace_id)
        .await
        .map_err(map_service_error)?
        .into_iter()
        .find(|m| m.user_id == member_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(member_response_from(updated)))
}

#[utoipa::path(
    delete,
    path = "/api/workspaces/{id}/members/{user_id}",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace ID"),
        ("user_id" = Uuid, Path, description = "Target user ID"),
    ),
    responses((status = 204))
)]
pub async fn remove_member(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path((workspace_id, member_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, StatusCode> {
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_permission(&ctx, workspace_id, user_id, PERM_MEMBER_REMOVE).await?;
    ctx.workspace_service()
        .remove_member(workspace_id, member_id, Some(user_id))
        .await
        .map_err(map_service_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/workspaces/{id}/leave",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    responses((status = 204))
)]
pub async fn leave_workspace(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(workspace_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    ctx.workspace_service()
        .leave_workspace(workspace_id, user_id)
        .await
        .map_err(map_service_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/workspaces/{id}/switch",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    responses((status = 200, body = SwitchWorkspaceResponse))
)]
pub async fn switch_workspace(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<(HeaderMap, Json<SwitchWorkspaceResponse>), StatusCode> {
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    ctx.workspace_service()
        .set_default_workspace(user_id, id)
        .await
        .map_err(map_service_error)?;
    let client_ip = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);
    let session_service = ctx.session_service();
    let mut issued = None;
    if let Some(refresh_token) = extract_refresh_token(&headers) {
        match session_service
            .refresh_session(
                &refresh_token,
                Some(id),
                SessionMetadata {
                    user_agent,
                    ip_address: client_ip.as_deref(),
                },
            )
            .await
        {
            Ok(bundle) => issued = Some(bundle),
            Err(ServiceError::Unauthorized | ServiceError::TokenExpired) => {
                issued = None;
            }
            Err(err) => return Err(auth::map_auth_error(err)),
        }
    }
    let issued = match issued {
        Some(bundle) => bundle,
        None => session_service
            .issue_new_session(
                user_id,
                id,
                false,
                SessionMetadata {
                    user_agent,
                    ip_address: client_ip.as_deref(),
                },
            )
            .await
            .map_err(auth::map_auth_error)?,
    };
    let mut response_headers = HeaderMap::new();
    apply_session_cookies(&ctx, &mut response_headers, &issued);
    Ok((
        response_headers,
        Json(SwitchWorkspaceResponse {
            access_token: issued.access.token,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/workspaces/{id}/permissions",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    responses((status = 200, body = WorkspacePermissionsResponse))
)]
pub async fn get_workspace_permissions(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
) -> Result<Json<WorkspacePermissionsResponse>, StatusCode> {
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let set = ctx
        .workspace_service()
        .resolve_permission_set(id, user_id)
        .await
        .map_err(map_service_error)?
        .ok_or(StatusCode::FORBIDDEN)?;
    Ok(Json(WorkspacePermissionsResponse {
        workspace_id: id,
        permissions: set.to_vec(),
    }))
}

#[utoipa::path(
    post,
    path = "/api/workspace-invitations/{token}/accept",
    tag = "Workspaces",
    params(("token" = String, Path, description = "Invitation token")),
    responses((status = 204))
)]
pub async fn accept_invitation(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(token): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let user = ctx
        .account_service()
        .get_me(user_id)
        .await
        .map_err(|err| match err {
            ServiceError::Unauthorized | ServiceError::TokenExpired => StatusCode::UNAUTHORIZED,
            ServiceError::Forbidden => StatusCode::FORBIDDEN,
            ServiceError::NotFound => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        })?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    ctx.workspace_service()
        .accept_invitation(&token, user_id, &user.email)
        .await
        .map_err(map_service_error)?;

    Ok(StatusCode::NO_CONTENT)
}
