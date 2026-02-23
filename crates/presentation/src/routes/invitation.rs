//! Invitation acceptance route (top-level, PoP-protected)

use application::workspace::AcceptInvitationCommand;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{AppState, WorkspaceSubState};
use crate::auth::PopVerifiedUser;
use super::app_error_response;

super::error_response_struct!(InvitationErrorResponse, "invitation error");

/// Accept invitation request
#[derive(Debug, Deserialize, ToSchema)]
pub struct AcceptInvitationRequest {
    /// Raw base64url-encoded invitation token (32 bytes when decoded)
    pub token: String,
}

/// Accept invitation response
#[derive(Debug, Serialize, ToSchema)]
pub struct AcceptInvitationResponse {
    pub workspace_id: String,
    pub workspace_name: String,
    pub role_name: Option<String>,
    pub invitation_id: String,
    pub encrypted_kek: String,
    pub kek_nonce: String,
    pub kek_version: i32,
}

/// PoP-protected invitation routes
pub fn pop_routes(state: AppState) -> Router {
    Router::new()
        .route("/accept", post(accept_invitation))
        .with_state(state)
}

/// Accept an invitation
#[utoipa::path(
    post,
    path = "/api/invitations/accept",
    request_body = AcceptInvitationRequest,
    responses(
        (status = 200, description = "Invitation accepted", body = AcceptInvitationResponse),
        (status = 400, description = "Invalid token format or length", body = InvitationErrorResponse),
        (status = 401, description = "Not authenticated", body = InvitationErrorResponse),
        (status = 403, description = "PoP verification failed", body = InvitationErrorResponse),
        (status = 404, description = "Invitation not found", body = InvitationErrorResponse),
        (status = 409, description = "KEK rotation in progress", body = InvitationErrorResponse),
        (status = 410, description = "Invitation expired/revoked/exhausted", body = InvitationErrorResponse),
    ),
    tag = "invitation"
)]
pub async fn accept_invitation(
    State(state): State<WorkspaceSubState>,
    pop_user: PopVerifiedUser,
    Json(request): Json<AcceptInvitationRequest>,
) -> impl IntoResponse {
    let handler = state.accept_invitation_handler();

    let command = AcceptInvitationCommand {
        token: request.token,
        user_id: pop_user.user_id,
    };

    match handler.handle(command).await {
        Ok(result) => (
            StatusCode::OK,
            Json(AcceptInvitationResponse {
                workspace_id: result.workspace_id.to_string(),
                workspace_name: result.workspace_name,
                role_name: result.role_name,
                invitation_id: result.invitation_id.to_string(),
                encrypted_kek: base64_url::encode(&result.encrypted_kek),
                kek_nonce: base64_url::encode(&result.kek_nonce),
                kek_version: result.kek_version,
            }),
        )
            .into_response(),
        Err(e) => app_error_response!(e, InvitationErrorResponse, bad_request, not_found, forbidden, conflict, gone),
    }
}
