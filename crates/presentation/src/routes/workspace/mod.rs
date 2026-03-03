//! Workspace routes
//!
//! - `pop_routes`: Read operations behind PoP middleware (list, get)
//! - `session_routes`: Management operations with session auth (create, update, delete, roles)

pub mod crud;
pub mod events;
pub mod invitations;
pub mod member_devices;
pub mod members;
pub mod roles;

use application::workspace::{
    GetWorkspaceQuery, ListUserWorkspacesQuery,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{AppState, WorkspaceSubState};
use crate::auth::PopVerifiedUser;
use super::app_error_response;

/// Workspace routes requiring PoP verification (behind PopLayer)
pub fn pop_routes(state: AppState) -> Router {
    Router::new()
        .route("/", get(list_workspaces))
        .route("/{workspace_id}", get(get_workspace))
        .with_state(state)
}

/// Invitation routes requiring PoP verification (behind PopLayer)
pub fn invitation_routes(state: AppState) -> Router {
    use axum::routing::{post, delete};

    Router::new()
        .route("/{workspace_id}/invitations", get(invitations::list_invitations))
        .route("/{workspace_id}/invitations", post(invitations::create_invitation))
        .route(
            "/{workspace_id}/invitations/{invitation_id}",
            delete(invitations::revoke_invitation),
        )
        .with_state(state)
}

/// Workspace routes requiring session auth only (no PoP)
pub fn session_routes(state: AppState) -> Router {
    use axum::routing::{post, patch, delete};

    Router::new()
        // Workspace CRUD
        .route("/", post(crud::create_workspace))
        .route("/{workspace_id}", patch(crud::update_workspace))
        .route("/{workspace_id}", delete(crud::delete_workspace))
        // Role CRUD
        .route("/{workspace_id}/roles", get(roles::list_roles))
        .route("/{workspace_id}/roles", post(roles::create_role))
        .route("/{workspace_id}/roles/{role_id}", patch(roles::update_role))
        .route("/{workspace_id}/roles/{role_id}", delete(roles::delete_role))
        // Member management
        .route("/{workspace_id}/members", get(members::list_members))
        .route("/{workspace_id}/members/{user_id}", patch(members::change_member_role))
        .route("/{workspace_id}/members/{user_id}", delete(members::remove_member))
        .route("/{workspace_id}/members/{user_id}/devices", get(member_devices::list_member_devices))
        // SSE events
        .route("/events", get(events::workspace_events))
        .with_state(state)
}

/// Workspace response
#[derive(Debug, Serialize, ToSchema)]
pub struct WorkspaceResponse {
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub id: String,
    #[schema(example = "My Workspace")]
    pub name: String,
    #[schema(example = "my-workspace")]
    pub slug: String,
    pub description: Option<String>,
    pub icon: Option<String>,
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub owner_id: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Workspace membership response
#[derive(Debug, Serialize, ToSchema)]
pub struct MembershipResponse {
    pub is_default: bool,
    pub role: RoleResponse,
}

/// Role response
#[derive(Debug, Serialize, ToSchema)]
pub struct RoleResponse {
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub id: String,
    #[schema(example = "owner")]
    pub name: String,
    #[schema(example = "owner")]
    pub base_role: String,
    pub is_default: bool,
}

/// Workspace with membership response
#[derive(Debug, Serialize, ToSchema)]
pub struct WorkspaceWithMembershipResponse {
    pub workspace: WorkspaceResponse,
    pub membership: MembershipResponse,
}

impl WorkspaceWithMembershipResponse {
    pub(crate) fn from_dtos(
        workspace: application::dto::WorkspaceDto,
        membership: application::dto::WorkspaceMemberDto,
        role: application::dto::WorkspaceRoleDto,
    ) -> Self {
        Self {
            workspace: WorkspaceResponse {
                id: workspace.id.to_string(),
                name: workspace.name,
                slug: workspace.slug,
                description: workspace.description,
                icon: workspace.icon,
                owner_id: workspace.owner_id.to_string(),
                created_at: workspace.created_at.to_rfc3339(),
                updated_at: workspace.updated_at.to_rfc3339(),
            },
            membership: MembershipResponse {
                is_default: membership.is_default,
                role: RoleResponse {
                    id: role.id.to_string(),
                    name: role.name,
                    base_role: role.base_role,
                    is_default: role.is_default,
                },
            },
        }
    }
}

/// List workspaces response
#[derive(Debug, Serialize, ToSchema)]
pub struct ListWorkspacesResponse {
    pub workspaces: Vec<WorkspaceWithMembershipResponse>,
}

super::error_response_struct!(WorkspaceErrorResponse, "workspace not found");

/// List user's workspaces
#[utoipa::path(
    get,
    path = "/api/workspaces",
    responses(
        (status = 200, description = "List of user's workspaces", body = ListWorkspacesResponse),
        (status = 401, description = "Not authenticated", body = WorkspaceErrorResponse),
        (status = 500, description = "Internal server error", body = WorkspaceErrorResponse),
    ),
    tag = "workspace"
)]
pub async fn list_workspaces(
    State(state): State<WorkspaceSubState>,
    pop_user: PopVerifiedUser,
) -> impl IntoResponse {
    let handler = state.list_workspaces_handler();

    let query = ListUserWorkspacesQuery { user_id: pop_user.user_id };

    match handler.handle(query).await {
        Ok(result) => {
            let workspaces = result
                .workspaces
                .into_iter()
                .map(|w| WorkspaceWithMembershipResponse::from_dtos(w.workspace, w.membership, w.role))
                .collect();

            (StatusCode::OK, Json(ListWorkspacesResponse { workspaces })).into_response()
        }
        Err(e) => app_error_response!(e, WorkspaceErrorResponse)
    }
}

/// Get workspace details
#[utoipa::path(
    get,
    path = "/api/workspaces/{workspace_id}",
    params(
        ("workspace_id" = Uuid, Path, description = "Workspace ID")
    ),
    responses(
        (status = 200, description = "Workspace details", body = WorkspaceWithMembershipResponse),
        (status = 401, description = "Not authenticated", body = WorkspaceErrorResponse),
        (status = 403, description = "Not a member of this workspace", body = WorkspaceErrorResponse),
        (status = 404, description = "Workspace not found", body = WorkspaceErrorResponse),
    ),
    tag = "workspace"
)]
pub async fn get_workspace(
    State(state): State<WorkspaceSubState>,
    pop_user: PopVerifiedUser,
    Path(workspace_id): Path<Uuid>,
) -> impl IntoResponse {
    let handler = state.get_workspace_handler();

    let query = GetWorkspaceQuery {
        workspace_id: application::types::WorkspaceId::from_uuid(workspace_id),
        user_id: pop_user.user_id,
    };

    match handler.handle(query).await {
        Ok(result) => {
            let response = WorkspaceWithMembershipResponse::from_dtos(
                result.workspace,
                result.membership,
                result.role,
            );
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => app_error_response!(e, WorkspaceErrorResponse, not_found, forbidden),
    }
}
