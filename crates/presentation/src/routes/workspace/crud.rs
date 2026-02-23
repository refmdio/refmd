//! Workspace CRUD routes: create, update, delete

use application::workspace::{
    CreateWorkspaceCommand, DeleteWorkspaceCommand, UpdateWorkspaceCommand,
};
use application::types::WorkspaceId;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::WorkspaceSubState;
use crate::auth::AuthUser;
use crate::routes::app_error_response;
use super::{WorkspaceErrorResponse, WorkspaceWithMembershipResponse};

/// Create workspace request
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWorkspaceRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// Create a new workspace
#[utoipa::path(
    post,
    path = "/api/workspaces",
    request_body = CreateWorkspaceRequest,
    responses(
        (status = 201, description = "Workspace created", body = WorkspaceWithMembershipResponse),
        (status = 400, description = "Invalid input", body = WorkspaceErrorResponse),
        (status = 401, description = "Not authenticated", body = WorkspaceErrorResponse),
    ),
    tag = "workspace"
)]
pub async fn create_workspace(
    State(state): State<WorkspaceSubState>,
    auth_user: AuthUser,
    Json(request): Json<CreateWorkspaceRequest>,
) -> impl IntoResponse {
    let handler = state.create_workspace_handler();

    let command = CreateWorkspaceCommand {
        user_id: auth_user.user_id,
        name: request.name,
        description: request.description,
    };

    match handler.handle(command).await {
        Ok(result) => {
            let response = WorkspaceWithMembershipResponse::from_dtos(
                result.workspace,
                result.membership,
                result.role,
            );
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(e) => app_error_response!(e, WorkspaceErrorResponse, bad_request, conflict),
    }
}

/// Update workspace request
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateWorkspaceRequest {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub description: Option<Option<String>>,
    pub icon: Option<Option<String>>,
}

/// Update a workspace
#[utoipa::path(
    patch,
    path = "/api/workspaces/{workspace_id}",
    params(("workspace_id" = Uuid, Path, description = "Workspace ID")),
    request_body = UpdateWorkspaceRequest,
    responses(
        (status = 200, description = "Workspace updated", body = super::WorkspaceResponse),
        (status = 400, description = "Invalid input", body = WorkspaceErrorResponse),
        (status = 401, description = "Not authenticated", body = WorkspaceErrorResponse),
        (status = 403, description = "Permission denied", body = WorkspaceErrorResponse),
        (status = 404, description = "Workspace not found", body = WorkspaceErrorResponse),
    ),
    tag = "workspace"
)]
pub async fn update_workspace(
    State(state): State<WorkspaceSubState>,
    Path(workspace_id): Path<Uuid>,
    auth_user: AuthUser,
    Json(request): Json<UpdateWorkspaceRequest>,
) -> impl IntoResponse {
    let handler = state.update_workspace_handler();

    let command = UpdateWorkspaceCommand {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        user_id: auth_user.user_id,
        name: request.name,
        slug: request.slug,
        description: request.description,
        icon: request.icon,
    };

    match handler.handle(command).await {
        Ok(result) => {
            let ws = result.workspace;
            (StatusCode::OK, Json(super::WorkspaceResponse {
                id: ws.id.to_string(),
                name: ws.name,
                slug: ws.slug,
                description: ws.description,
                icon: ws.icon,
                owner_id: ws.owner_id.to_string(),
                created_at: ws.created_at.to_rfc3339(),
                updated_at: ws.updated_at.to_rfc3339(),
            })).into_response()
        }
        Err(e) => app_error_response!(e, WorkspaceErrorResponse, bad_request, not_found, forbidden, conflict),
    }
}

/// Delete a workspace
#[utoipa::path(
    delete,
    path = "/api/workspaces/{workspace_id}",
    params(("workspace_id" = Uuid, Path, description = "Workspace ID")),
    responses(
        (status = 204, description = "Workspace deleted"),
        (status = 401, description = "Not authenticated", body = WorkspaceErrorResponse),
        (status = 403, description = "Permission denied", body = WorkspaceErrorResponse),
        (status = 404, description = "Workspace not found", body = WorkspaceErrorResponse),
    ),
    tag = "workspace"
)]
pub async fn delete_workspace(
    State(state): State<WorkspaceSubState>,
    Path(workspace_id): Path<Uuid>,
    auth_user: AuthUser,
) -> impl IntoResponse {
    let handler = state.delete_workspace_handler();

    let command = DeleteWorkspaceCommand {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        user_id: auth_user.user_id,
    };

    match handler.handle(command).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => app_error_response!(e, WorkspaceErrorResponse, not_found, forbidden),
    }
}
