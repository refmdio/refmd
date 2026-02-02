//! Presentation layer - HTTP interface
//!
//! This layer contains:
//! - HTTP routes: Axum route definitions
//! - WebSocket: Real-time communication (Yjs sync)
//! - Request/Response transformation: JSON to/from DTOs
//! - Authentication middleware: Session validation, authorization

// Re-export application for convenience
pub use application;

mod state;
pub mod routes;

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
        routes::users::register_user,
    ),
    components(
        schemas(
            routes::users::RegisterUserRequest,
            routes::users::RegisterUserResponse,
            routes::users::ErrorResponse,
        )
    ),
    tags(
        (name = "users", description = "User management endpoints"),
    )
)]
pub struct ApiDoc;
