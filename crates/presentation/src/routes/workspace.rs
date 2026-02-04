//! Workspace routes

use application::domain::document::{DocumentRepository, DocumentUpdateRepository};
use application::domain::encryption::{
    DeviceEncryptedUMKRepository, DeviceRepository, DocumentEncryptedKeyRepository,
    PendingDeviceRepository, UserEncryptedIdentityKeyRepository, UserEncryptedMasterKeyRepository,
    UserIdentityPublicKeyRepository, WorkspaceEncryptedKeyRepository,
};
use application::domain::identity::{SessionRepository, UserRepository, UserSettingsRepository};
use application::domain::workspace::{
    WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRoleRepository,
};
use application::identity::RegistrationService;
use application::workspace::{
    GetWorkspaceHandler, GetWorkspaceQuery, ListUserWorkspacesHandler, ListUserWorkspacesQuery,
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

use crate::AppState;
use crate::auth::verify_pop;

/// Create workspace routes
pub fn routes<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    state: AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
) -> Router
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    Router::new()
        .route(
            "/",
            get(list_workspaces::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>),
        )
        .route(
            "/{id}",
            get(get_workspace::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>),
        )
        .nest(
            "/{workspace_id}/documents",
            super::document::workspace_routes::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(),
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

/// List workspaces response
#[derive(Debug, Serialize, ToSchema)]
pub struct ListWorkspacesResponse {
    /// List of workspaces with membership info
    pub workspaces: Vec<WorkspaceWithMembershipResponse>,
}

/// Workspace error response
#[derive(Debug, Serialize, ToSchema)]
pub struct WorkspaceErrorResponse {
    /// Error message
    #[schema(example = "workspace not found")]
    pub error: String,
}

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
pub async fn list_workspaces<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    // Authenticate user
    let user = match authenticate_user(&state, &headers).await {
        Ok(u) => u,
        Err(response) => return response,
    };

    let handler = ListUserWorkspacesHandler::new(
        state.workspace_repo(),
        state.workspace_member_repo(),
        state.workspace_role_repo(),
    );

    let query = ListUserWorkspacesQuery { user_id: user.id };

    match handler.handle(query).await {
        Ok(result) => {
            let workspaces = result
                .workspaces
                .into_iter()
                .map(|w| WorkspaceWithMembershipResponse {
                    workspace: WorkspaceResponse {
                        id: w.workspace.id.to_string(),
                        name: w.workspace.name.clone(),
                        slug: w.workspace.slug.to_string(),
                        owner_id: w.workspace.owner_id.to_string(),
                        created_at: w.workspace.created_at.to_rfc3339(),
                        updated_at: w.workspace.updated_at.to_rfc3339(),
                    },
                    membership: MembershipResponse {
                        is_default: w.membership.is_default,
                        role: RoleResponse {
                            id: w.role.id.to_string(),
                            name: w.role.name.clone(),
                            base_role: w.role.base_role.to_string(),
                        },
                    },
                })
                .collect();

            (StatusCode::OK, Json(ListWorkspacesResponse { workspaces })).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to list workspaces: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(WorkspaceErrorResponse {
                    error: "internal server error".to_string(),
                }),
            )
                .into_response()
        }
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
pub async fn get_workspace<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    // Authenticate user
    let user = match authenticate_user(&state, &headers).await {
        Ok(u) => u,
        Err(response) => return response,
    };

    let handler = GetWorkspaceHandler::new(
        state.workspace_repo(),
        state.workspace_member_repo(),
        state.workspace_role_repo(),
    );

    let query = GetWorkspaceQuery {
        workspace_id: application::domain::workspace::WorkspaceId::from_uuid(id),
        user_id: user.id,
    };

    match handler.handle(query).await {
        Ok(result) => {
            let response = WorkspaceWithMembershipResponse {
                workspace: WorkspaceResponse {
                    id: result.workspace.id.to_string(),
                    name: result.workspace.name.clone(),
                    slug: result.workspace.slug.to_string(),
                    owner_id: result.workspace.owner_id.to_string(),
                    created_at: result.workspace.created_at.to_rfc3339(),
                    updated_at: result.workspace.updated_at.to_rfc3339(),
                },
                membership: MembershipResponse {
                    is_default: result.membership.is_default,
                    role: RoleResponse {
                        id: result.role.id.to_string(),
                        name: result.role.name.clone(),
                        base_role: result.role.base_role.to_string(),
                    },
                },
            };

            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            if e.is_not_found() {
                (
                    StatusCode::NOT_FOUND,
                    Json(WorkspaceErrorResponse {
                        error: "workspace not found".to_string(),
                    }),
                )
                    .into_response()
            } else if e.is_forbidden() {
                (
                    StatusCode::FORBIDDEN,
                    Json(WorkspaceErrorResponse {
                        error: "not a member of this workspace".to_string(),
                    }),
                )
                    .into_response()
            } else {
                tracing::error!("Failed to get workspace: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(WorkspaceErrorResponse {
                        error: "internal server error".to_string(),
                    }),
                )
                    .into_response()
            }
        }
    }
}

/// Authenticated user info (minimal)
struct AuthenticatedUser {
    id: application::domain::identity::UserId,
}

/// Authenticate user from session cookie
async fn authenticate_user<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    state: &AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    headers: &axum::http::HeaderMap,
) -> Result<AuthenticatedUser, axum::response::Response>
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    // Extract session token from cookie
    let token = match crate::auth::extract_session_token(headers) {
        Ok(t) => t,
        Err(e) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(WorkspaceErrorResponse { error: e.error }),
            )
                .into_response());
        }
    };

    // Hash the token
    let token_hash = crate::auth::hash_session_token(token);

    // Validate session
    let session_repo = state.session_repo();
    let session = match session_repo.find_by_token_hash(&token_hash).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(WorkspaceErrorResponse {
                    error: "invalid session".to_string(),
                }),
            )
                .into_response());
        }
        Err(e) => {
            tracing::error!("Failed to find session: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(WorkspaceErrorResponse {
                    error: "internal server error".to_string(),
                }),
            )
                .into_response());
        }
    };

    // Check if session is expired
    if session.is_expired() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(WorkspaceErrorResponse {
                error: "session expired".to_string(),
            }),
        )
            .into_response());
    }

    // Verify PoP (Proof of Possession) - required for E2EE key operations
    if let Err(e) = verify_pop(
        headers,
        session.user_id,
        state.device_repo().as_ref(),
        &state.challenge_cache(),
    )
    .await
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(WorkspaceErrorResponse { error: e.error }),
        )
            .into_response());
    }

    Ok(AuthenticatedUser {
        id: session.user_id,
    })
}
