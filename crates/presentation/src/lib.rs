//! Presentation layer - HTTP interface
//!
//! This layer contains:
//! - HTTP routes: Axum route definitions
//! - WebSocket: Real-time communication (Yjs sync)
//! - Request/Response transformation: JSON to/from DTOs
//! - Authentication middleware: Session validation, authorization

// Allow type_complexity for AppState generics - this is by design for DI
#![allow(clippy::type_complexity)]

// Re-export application for convenience
pub use application;

pub mod auth;
pub mod routes;
mod state;

pub use auth::{AuthUser, AuthUserFull};
pub use state::{AppState, AppStateParams};

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
        routes::document::list_documents,
        routes::document::create_document,
        routes::document::get_document,
        routes::document::update_document,
        routes::document::delete_document,
        routes::document::archive_document,
        routes::document::unarchive_document,
        routes::document::list_updates,
        routes::document::create_update,
        routes::encryption::save_workspace_key,
        routes::encryption::get_workspace_key,
        routes::encryption::save_document_key,
        routes::encryption::get_document_key,
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
            routes::document::DocumentResponse,
            routes::document::CreateDocumentRequest,
            routes::document::UpdateDocumentRequest,
            routes::document::ListDocumentsParams,
            routes::document::ListDocumentsResponse,
            routes::document::DocumentErrorResponse,
            routes::document::DocumentUpdateResponse,
            routes::document::ListDocumentUpdatesResponse,
            routes::document::ListDocumentUpdatesParams,
            routes::document::CreateDocumentUpdateRequest,
            routes::document::CreateDocumentUpdateResponse,
            routes::encryption::SaveWorkspaceKeyRequest,
            routes::encryption::WorkspaceKeyResponse,
            routes::encryption::GetWorkspaceKeyParams,
            routes::encryption::SaveDocumentKeyRequest,
            routes::encryption::DocumentKeyResponse,
            routes::encryption::EncryptionErrorResponse,
        )
    ),
    tags(
        (name = "auth", description = "Authentication endpoints"),
        (name = "workspace", description = "Workspace management endpoints"),
        (name = "document", description = "Document management endpoints"),
        (name = "encryption", description = "Encryption key management endpoints"),
    )
)]
pub struct ApiDoc;
