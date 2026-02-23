//! Workspace invitation routes: create, list, revoke (all PoP-protected)

use application::workspace::{
    CreateInvitationCommand, ListInvitationsQuery, RevokeInvitationCommand,
};
use application::types::{InvitationId, RoleId, WorkspaceId};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::WorkspaceSubState;
use crate::auth::PopVerifiedUser;
use crate::routes::app_error_response;
use super::WorkspaceErrorResponse;

// ── Response structs (matching design doc exactly) ──

/// Create invitation response (201 Created)
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateInvitationResponse {
    pub invitation_id: String,
    pub workspace_id: String,
    pub token_prefix: String,
    pub role_id: String,
    pub invited_email: String,
    pub kek_version: i32,
    pub is_used: bool,
    pub expires_at: String,
    pub created_at: String,
}

/// Invitation list item (GET response)
#[derive(Debug, Serialize, ToSchema)]
pub struct InvitationListItem {
    pub invitation_id: String,
    pub workspace_id: String,
    pub token_prefix: String,
    pub role_id: Option<String>,
    pub role_name: Option<String>,
    pub invited_by: String,
    pub invited_email: String,
    pub kek_version: i32,
    pub is_used: bool,
    pub expires_at: String,
    pub created_at: String,
}

/// List invitations response
#[derive(Debug, Serialize, ToSchema)]
pub struct ListInvitationsResponse {
    pub invitations: Vec<InvitationListItem>,
}

// ── Request structs ──

/// Create invitation request
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateInvitationRequest {
    /// Must be canonical lowercase-hyphenated UUID (e.g. "550e8400-e29b-41d4-a716-446655440000").
    /// Non-canonical formats are rejected to prevent AAD mismatch: the client builds AAD from
    /// this string, so it must round-trip exactly through `Uuid::to_string()`.
    pub invitation_id: String,
    pub token_hash: String,
    pub token_prefix: String,
    pub role_id: Option<Uuid>,
    pub invited_email: String,
    pub encrypted_kek: String,
    pub kek_nonce: String,
    pub kek_version: i32,
    pub expires_at: Option<DateTime<Utc>>,
}

// ── Handlers ──

/// List invitations
#[utoipa::path(
    get,
    path = "/api/workspaces/{workspace_id}/invitations",
    params(("workspace_id" = Uuid, Path, description = "Workspace ID")),
    responses(
        (status = 200, description = "List of active invitations", body = ListInvitationsResponse),
        (status = 401, description = "Not authenticated", body = WorkspaceErrorResponse),
        (status = 403, description = "Permission denied", body = WorkspaceErrorResponse),
        (status = 404, description = "Not found", body = WorkspaceErrorResponse),
    ),
    tag = "workspace"
)]
pub async fn list_invitations(
    State(state): State<WorkspaceSubState>,
    Path(workspace_id): Path<Uuid>,
    pop_user: PopVerifiedUser,
) -> impl IntoResponse {
    let handler = state.list_invitations_handler();

    let query = ListInvitationsQuery {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        user_id: pop_user.user_id,
    };

    match handler.handle(query).await {
        Ok(result) => {
            let invitations = result
                .invitations
                .into_iter()
                .map(|item| InvitationListItem {
                    invitation_id: item.invitation.id.to_string(),
                    workspace_id: item.invitation.workspace_id.to_string(),
                    token_prefix: item.invitation.token_prefix,
                    role_id: item.invitation.role_id.map(|r| r.to_string()),
                    role_name: item.role_name,
                    invited_by: item.invitation.invited_by.to_string(),
                    invited_email: item.invitation.invited_email,
                    kek_version: item.invitation.kek_version,
                    is_used: item.invitation.is_used,
                    expires_at: item.invitation.expires_at.to_rfc3339(),
                    created_at: item.invitation.created_at.to_rfc3339(),
                })
                .collect();
            (
                StatusCode::OK,
                Json(ListInvitationsResponse { invitations }),
            )
                .into_response()
        }
        Err(e) => app_error_response!(e, WorkspaceErrorResponse, not_found, forbidden),
    }
}

/// Create an invitation
#[utoipa::path(
    post,
    path = "/api/workspaces/{workspace_id}/invitations",
    params(("workspace_id" = Uuid, Path, description = "Workspace ID")),
    request_body = CreateInvitationRequest,
    responses(
        (status = 201, description = "Invitation created", body = CreateInvitationResponse),
        (status = 400, description = "Invalid input", body = WorkspaceErrorResponse),
        (status = 401, description = "Not authenticated", body = WorkspaceErrorResponse),
        (status = 403, description = "Permission denied", body = WorkspaceErrorResponse),
        (status = 404, description = "Not found", body = WorkspaceErrorResponse),
        (status = 409, description = "KEK rotation in progress", body = WorkspaceErrorResponse),
        (status = 422, description = "KEK version mismatch", body = WorkspaceErrorResponse),
    ),
    tag = "workspace"
)]
pub async fn create_invitation(
    State(state): State<WorkspaceSubState>,
    Path(workspace_id): Path<Uuid>,
    pop_user: PopVerifiedUser,
    Json(request): Json<CreateInvitationRequest>,
) -> impl IntoResponse {
    // Validate invitation_id is a canonical lowercase-hyphenated UUID.
    // The client uses this string as part of AAD for KEK encryption, so non-canonical
    // formats (uppercase, missing hyphens) would cause an AAD mismatch on decryption.
    let invitation_uuid = match Uuid::parse_str(&request.invitation_id) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(WorkspaceErrorResponse {
                    error: "invitation_id is not a valid UUID".to_string(),
                }),
            )
                .into_response();
        }
    };
    if invitation_uuid.to_string() != request.invitation_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(WorkspaceErrorResponse {
                error: "invitation_id must be canonical lowercase hyphenated UUID format"
                    .to_string(),
            }),
        )
            .into_response();
    }

    // Validate base64url string lengths before decoding to prevent oversized payloads.
    // encrypted_kek: 48 bytes → 64 base64url chars max (ceil(48/3)*4 = 64)
    // kek_nonce: 24 bytes → 32 base64url chars max (ceil(24/3)*4 = 32)
    if request.encrypted_kek.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(WorkspaceErrorResponse {
                error: "encrypted_kek too long (max 64 base64url chars)".to_string(),
            }),
        )
            .into_response();
    }
    if request.kek_nonce.len() > 32 {
        return (
            StatusCode::BAD_REQUEST,
            Json(WorkspaceErrorResponse {
                error: "kek_nonce too long (max 32 base64url chars)".to_string(),
            }),
        )
            .into_response();
    }

    let encrypted_kek = match base64_url::decode(&request.encrypted_kek) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(WorkspaceErrorResponse {
                    error: "invalid base64url: encrypted_kek".to_string(),
                }),
            )
                .into_response()
        }
    };

    let kek_nonce = match base64_url::decode(&request.kek_nonce) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(WorkspaceErrorResponse {
                    error: "invalid base64url: kek_nonce".to_string(),
                }),
            )
                .into_response()
        }
    };

    let handler = state.create_invitation_handler();

    let command = CreateInvitationCommand {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        invitation_id: InvitationId::from_uuid(invitation_uuid),
        user_id: pop_user.user_id,
        token_hash: request.token_hash,
        token_prefix: request.token_prefix,
        role_id: request.role_id.map(RoleId::from_uuid),
        invited_email: request.invited_email,
        encrypted_kek,
        kek_nonce,
        kek_version: request.kek_version,
        expires_at: request.expires_at,
    };

    match handler.handle(command).await {
        Ok(result) => {
            let inv = result.invitation;

            // role_id must be present for a successfully created invitation.
            // If it is NULL, it indicates a data integrity issue — return 500.
            let Some(role_id) = inv.role_id else {
                tracing::error!("invitation {} has NULL role_id after creation", inv.id);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(WorkspaceErrorResponse {
                        error: "internal error: invitation role_id is null".to_string(),
                    }),
                )
                    .into_response();
            };
            (
                StatusCode::CREATED,
                Json(CreateInvitationResponse {
                    invitation_id: inv.id.to_string(),
                    workspace_id: inv.workspace_id.to_string(),
                    token_prefix: inv.token_prefix,
                    role_id: role_id.to_string(),
                    invited_email: inv.invited_email,
                    kek_version: inv.kek_version,
                    is_used: inv.is_used,
                    expires_at: inv.expires_at.to_rfc3339(),
                    created_at: inv.created_at.to_rfc3339(),
                }),
            )
                .into_response()
        }
        Err(e) => app_error_response!(
            e,
            WorkspaceErrorResponse,
            bad_request,
            not_found,
            forbidden,
            conflict,
            unprocessable
        ),
    }
}

/// Revoke an invitation
#[utoipa::path(
    delete,
    path = "/api/workspaces/{workspace_id}/invitations/{invitation_id}",
    params(
        ("workspace_id" = Uuid, Path, description = "Workspace ID"),
        ("invitation_id" = Uuid, Path, description = "Invitation ID"),
    ),
    responses(
        (status = 204, description = "Invitation revoked"),
        (status = 401, description = "Not authenticated", body = WorkspaceErrorResponse),
        (status = 403, description = "Permission denied", body = WorkspaceErrorResponse),
        (status = 404, description = "Invitation not found", body = WorkspaceErrorResponse),
    ),
    tag = "workspace"
)]
pub async fn revoke_invitation(
    State(state): State<WorkspaceSubState>,
    Path((workspace_id, invitation_id)): Path<(Uuid, Uuid)>,
    pop_user: PopVerifiedUser,
) -> impl IntoResponse {
    let handler = state.revoke_invitation_handler();

    let command = RevokeInvitationCommand {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        user_id: pop_user.user_id,
        invitation_id: InvitationId::from_uuid(invitation_id),
    };

    match handler.handle(command).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            app_error_response!(e, WorkspaceErrorResponse, not_found, forbidden)
        }
    }
}
