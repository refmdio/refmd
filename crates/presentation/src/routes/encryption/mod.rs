//! Encryption key routes (KEK/DEK)
//!
//! These routes handle E2EE key material and require PoP (Proof of Possession)
//! verification.

mod document_keys;
mod workspace_keys;

pub use document_keys::*;
pub use workspace_keys::*;

use axum::{Router, routing::post};

use crate::AppState;

/// Create encryption routes
pub fn routes(state: AppState) -> Router {
    Router::new()
        // Workspace KEK endpoints
        .route(
            "/workspaces/{workspace_id}/keys",
            post(save_workspace_key).get(get_workspace_key),
        )
        // Workspace KEK backup endpoints (UMK-wrapped)
        .route(
            "/workspaces/{workspace_id}/kek-backup",
            post(save_workspace_kek_backup).get(get_workspace_kek_backup),
        )
        // KEK rotation completion endpoint
        .route(
            "/workspaces/{workspace_id}/kek-rotation/complete",
            post(complete_kek_rotation),
        )
        // Document DEK endpoints
        .route(
            "/documents/{document_id}/keys",
            post(save_document_key).get(get_document_key),
        )
        .with_state(state)
}

super::error_response_struct!(EncryptionErrorResponse, "key not found");
