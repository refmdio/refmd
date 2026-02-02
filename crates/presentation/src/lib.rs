//! Presentation layer - HTTP interface
//!
//! This layer contains:
//! - HTTP routes: Axum route definitions
//! - WebSocket: Real-time communication (Yjs sync)
//! - Request/Response transformation: JSON to/from DTOs
//! - Authentication middleware: Session validation, authorization

// Re-export application for convenience
pub use application;

pub mod auth;
mod state;
pub mod routes;

pub use auth::{AuthUser, AuthUserFull};
pub use state::AppState;

use utoipa::OpenApi;

/// OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    info(
        title = "RefMD API",
        version = "0.1.0",
        description = "RefMD E2EE Document Editor API"
    ),
    paths(
        routes::auth::get_salt,
        routes::auth::register,
        routes::auth::login,
        routes::auth::logout,
        routes::auth::me,
        routes::workspace::list_workspaces,
        routes::workspace::get_workspace,
    ),
    components(
        schemas(
            routes::auth::GetSaltQueryParams,
            routes::auth::GetSaltResponse,
            routes::auth::KdfParamsResponse,
            routes::auth::AuthErrorResponse,
            routes::auth::RegisterRequest,
            routes::auth::RegisterResponse,
            routes::auth::LoginRequest,
            routes::auth::LoginResponse,
            routes::auth::LogoutResponse,
            routes::auth::MeResponse,
            routes::workspace::WorkspaceResponse,
            routes::workspace::MembershipResponse,
            routes::workspace::RoleResponse,
            routes::workspace::WorkspaceWithMembershipResponse,
            routes::workspace::ListWorkspacesResponse,
            routes::workspace::WorkspaceErrorResponse,
        )
    ),
    tags(
        (name = "auth", description = "Authentication endpoints"),
        (name = "workspace", description = "Workspace management endpoints"),
    )
)]
pub struct ApiDoc;
