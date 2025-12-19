use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::context::AppContext;
use crate::security::token::{self, Bearer};
use crate::http::error::ApiError;
use application::core::services::errors::ServiceError;
use domain::access::permissions::PERM_MEMBER_INVITE;

use super::types::{
    CreateWorkspaceInvitationRequest, WorkspaceInvitationResponse, invitation_response_from,
    map_service_error, parse_role_kind, parse_system_role, require_permission,
};

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
) -> Result<Json<Vec<WorkspaceInvitationResponse>>, ApiError> {
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(token::map_actor_error)?;
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
) -> Result<Json<WorkspaceInvitationResponse>, ApiError> {
    if body.email.trim().is_empty() {
        return Err(ApiError::bad_request("invalid_email"));
    }
    let role_kind = parse_role_kind(body.role_kind.as_str())?;
    let system_role = parse_system_role(body.system_role.as_deref())?;
    match role_kind {
        domain::workspaces::roles::WorkspaceRoleKind::System => {
            if system_role.is_none() || body.custom_role_id.is_some() {
                return Err(ApiError::bad_request("invalid_role"));
            }
        }
        domain::workspaces::roles::WorkspaceRoleKind::Custom => {
            if system_role.is_some() || body.custom_role_id.is_none() {
                return Err(ApiError::bad_request("invalid_role"));
            }
        }
    }
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(token::map_actor_error)?;
    require_permission(&ctx, id, user_id, PERM_MEMBER_INVITE).await?;
    let record = ctx
        .workspace_service()
        .create_invitation(
            id,
            user_id,
            &body.email,
            role_kind,
            system_role,
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
) -> Result<Json<WorkspaceInvitationResponse>, ApiError> {
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(token::map_actor_error)?;
    require_permission(&ctx, workspace_id, user_id, PERM_MEMBER_INVITE).await?;
    let record = ctx
        .workspace_service()
        .revoke_invitation(workspace_id, invitation_id)
        .await
        .map_err(map_service_error)?;
    Ok(Json(invitation_response_from(record)))
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
) -> Result<StatusCode, ApiError> {
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(token::map_actor_error)?;
    let user = ctx
        .account_service()
        .get_me(user_id)
        .await
        .map_err(|err| match err {
            ServiceError::Unauthorized | ServiceError::TokenExpired => ApiError::unauthorized("unauthorized"),
            ServiceError::Forbidden => ApiError::forbidden("forbidden"),
            ServiceError::NotFound => ApiError::unauthorized("unauthorized"),
            ServiceError::BadRequest(code) => ApiError::bad_request(code).with_message(code),
            ServiceError::Conflict => ApiError::conflict("conflict"),
            ServiceError::Unexpected(_) => ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        })?
        .ok_or(ApiError::unauthorized("unauthorized"))?;

    ctx.workspace_service()
        .accept_invitation(&token, user_id, &user.email)
        .await
        .map_err(map_service_error)?;

    Ok(StatusCode::NO_CONTENT)
}
