//! Document routes

mod crud;
mod updates;

pub use crud::*;
pub use updates::*;

use application::dto::DocumentDto;
use axum::{
    Router,
    routing::{get, post},
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::AppState;

/// Create document routes under /api/workspaces/{workspace_id}/documents
///
/// Only for listing and creating documents (require workspace context).
pub fn workspace_routes() -> Router<AppState> {
    Router::new().route(
        "/",
        get(list_documents).post(create_document),
    )
}

/// Create document routes under /api/documents
///
/// For single document access by document ID only.
pub fn routes(state: AppState) -> Router {
    Router::new()
        .route(
            "/{document_id}",
            get(get_document)
                .patch(update_document)
                .delete(delete_document),
        )
        .route(
            "/{document_id}/archive",
            post(archive_document),
        )
        .route(
            "/{document_id}/unarchive",
            post(unarchive_document),
        )
        .route(
            "/{document_id}/updates",
            get(list_updates).post(create_update),
        )
        .with_state(state)
}

/// Document response
#[derive(Debug, Serialize, ToSchema)]
pub struct DocumentResponse {
    pub id: String,
    pub workspace_id: String,
    pub parent_id: Option<String>,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_title_nonce: Option<String>,
    pub slug: String,
    #[schema(nullable)]
    pub path: Option<String>,
    pub doc_type: String,
    pub is_encrypted: bool,
    pub is_archived: bool,
    pub needs_dek_rotation: bool,
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub archived_at: Option<String>,
}

super::error_response_struct!(DocumentErrorResponse);

// Helper to convert DocumentDto to DocumentResponse
pub(crate) fn document_to_response(doc: DocumentDto) -> DocumentResponse {
    DocumentResponse {
        id: doc.id.to_string(),
        workspace_id: doc.workspace_id.to_string(),
        parent_id: doc.parent_id.map(|id| id.to_string()),
        title: doc.title,
        encrypted_title: doc.encrypted_title.map(|v| base64_url::encode(&v)),
        encrypted_title_nonce: doc.encrypted_title_nonce.map(|v| base64_url::encode(&v)),
        slug: doc.slug,
        path: doc.path,
        doc_type: doc.doc_type,
        is_encrypted: doc.is_encrypted,
        is_archived: doc.is_archived,
        needs_dek_rotation: doc.needs_dek_rotation,
        created_by: doc.created_by.map(|id| id.to_string()),
        created_at: doc.created_at.to_rfc3339(),
        updated_at: doc.updated_at.to_rfc3339(),
        archived_at: doc.archived_at.map(|dt| dt.to_rfc3339()),
    }
}

/// Maximum encrypted title size (4 KB). Titles are short text; anything larger is likely abuse.
const MAX_ENCRYPTED_TITLE_BYTES: usize = 4096;

/// Decode optional base64url-encoded encrypted title fields.
#[allow(clippy::type_complexity)]
pub(crate) fn decode_encrypted_title_fields(
    encrypted_title: Option<String>,
    encrypted_title_nonce: Option<String>,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), (axum::http::StatusCode, axum::Json<DocumentErrorResponse>)> {
    let encrypted_title = encrypted_title
        .map(|s| {
            crate::crypto_validation::decode_b64_max(
                "encrypted_title",
                &s,
                MAX_ENCRYPTED_TITLE_BYTES,
            )
        })
        .transpose()
        .map_err(|(_status, msg)| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(DocumentErrorResponse { error: msg }),
            )
        })?;

    let encrypted_title_nonce = encrypted_title_nonce
        .map(|s| {
            crate::crypto_validation::decode_nonce("encrypted_title_nonce", &s)
        })
        .transpose()
        .map_err(|(_status, msg)| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(DocumentErrorResponse { error: msg }),
            )
        })?;

    Ok((encrypted_title, encrypted_title_nonce))
}
