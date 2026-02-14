//! Workspace routes

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

/// Create workspace routes
pub fn routes(state: AppState) -> Router {
    Router::new()
        .route("/", get(list_workspaces))
        .route("/{id}", get(get_workspace))
        .nest(
            "/{workspace_id}/documents",
            super::document::workspace_routes(),
        )
        .with_state(state)
}

/// Workspace response
#[derive(Debug, Serialize, ToSchema)]
pub struct WorkspaceResponse {
    /// Workspace ID (UUID)
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub id: String,
    /// Workspace name
    #[schema(example = "My Workspace")]
    pub name: String,
    /// Workspace slug
    #[schema(example = "my-workspace")]
    pub slug: String,
    /// Owner user ID
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub owner_id: String,
    /// Creation timestamp
    pub created_at: String,
    /// Last update timestamp
    pub updated_at: String,
}

/// Workspace membership response
#[derive(Debug, Serialize, ToSchema)]
pub struct MembershipResponse {
    /// Whether this is the user's default workspace
    pub is_default: bool,
    /// User's role in the workspace
    pub role: RoleResponse,
}

/// Role response
#[derive(Debug, Serialize, ToSchema)]
pub struct RoleResponse {
    /// Role ID
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub id: String,
    /// Role name
    #[schema(example = "owner")]
    pub name: String,
    /// Base role type
    #[schema(example = "owner")]
    pub base_role: String,
}

/// Workspace with membership response
#[derive(Debug, Serialize, ToSchema)]
pub struct WorkspaceWithMembershipResponse {
    /// Workspace details
    pub workspace: WorkspaceResponse,
    /// User's membership in the workspace
    pub membership: MembershipResponse,
}

impl WorkspaceWithMembershipResponse {
    fn from_dtos(
        workspace: application::dto::WorkspaceDto,
        membership: application::dto::WorkspaceMemberDto,
        role: application::dto::WorkspaceRoleDto,
    ) -> Self {
        Self {
            workspace: WorkspaceResponse {
                id: workspace.id.to_string(),
                name: workspace.name,
                slug: workspace.slug,
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
                },
            },
        }
    }
}

/// List workspaces response
#[derive(Debug, Serialize, ToSchema)]
pub struct ListWorkspacesResponse {
    /// List of workspaces with membership info
    pub workspaces: Vec<WorkspaceWithMembershipResponse>,
}

super::error_response_struct!(WorkspaceErrorResponse, "workspace not found");

/// List user's workspaces
///
/// Returns all workspaces the authenticated user is a member of.
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
///
/// Returns workspace details with membership info for the authenticated user.
#[utoipa::path(
    get,
    path = "/api/workspaces/{id}",
    params(
        ("id" = Uuid, Path, description = "Workspace ID")
    ),
    responses(
        (status = 200, description = "Workspace details", body = WorkspaceWithMembershipResponse),
        (status = 401, description = "Not authenticated", body = WorkspaceErrorResponse),
        (status = 403, description = "Not a member of this workspace", body = WorkspaceErrorResponse),
        (status = 404, description = "Workspace not found", body = WorkspaceErrorResponse),
        (status = 500, description = "Internal server error", body = WorkspaceErrorResponse),
    ),
    tag = "workspace"
)]
pub async fn get_workspace(
    State(state): State<WorkspaceSubState>,
    pop_user: PopVerifiedUser,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let handler = state.get_workspace_handler();

    let query = GetWorkspaceQuery {
        workspace_id: application::types::WorkspaceId::from_uuid(id),
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

