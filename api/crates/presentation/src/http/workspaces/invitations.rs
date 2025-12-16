use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid;

use application::services::errors::ServiceError;
use domain::workspaces::permissions::PERM_MEMBER_INVITE;
use crate::context::AppContext;
use crate::http::auth::Bearer;

use super::types::{
    CreateWorkspaceInvitationRequest, WorkspaceInvitationResponse, invitation_response_from,
    map_service_error, require_permission,
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
) -> Result<Json<Vec<WorkspaceInvitationResponse>>, StatusCode> {
    let sub = crate::http::auth::validate_bearer(&ctx, bearer).await?;
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
    let sub = crate::http::auth::validate_bearer(&ctx, bearer).await?;
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
    let sub = crate::http::auth::validate_bearer(&ctx, bearer).await?;
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
    let sub = crate::http::auth::validate_bearer(&ctx, bearer).await?;
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
