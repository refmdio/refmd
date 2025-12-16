mod content;
mod crud;
mod links;
mod search;
mod snapshots;
pub mod types;

use axum::{routing::{get, post}, Router};

use crate::presentation::context::AppContext;

// Re-export handlers and schemas so OpenAPI can locate generated __path_* items.
pub use content::*;
pub use crud::*;
pub use links::*;
pub use search::*;
pub use snapshots::*;
pub use types::*;

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/documents", get(list_documents).post(create_document))
        .route(
            "/documents/:id",
            get(get_document)
                .delete(delete_document)
                .patch(update_document),
        )
        .route(
            "/documents/:id/content",
            get(get_document_content)
                .put(update_document_content)
                .patch(patch_document_content),
        )
        .route("/documents/:id/duplicate", post(duplicate_document))
        .route("/documents/:id/archive", post(archive_document))
        .route("/documents/:id/unarchive", post(unarchive_document))
        .route("/documents/:id/snapshots", get(list_document_snapshots))
        .route(
            "/documents/:id/snapshots/:snapshot_id/diff",
            get(get_document_snapshot_diff),
        )
        .route(
            "/documents/:id/snapshots/:snapshot_id/restore",
            post(restore_document_snapshot),
        )
        .route(
            "/documents/:id/snapshots/:snapshot_id/download",
            get(download_document_snapshot),
        )
        .route("/documents/:id/download", get(download_document))
        .route("/documents/:id/backlinks", get(get_backlinks))
        .route("/documents/:id/links", get(get_outgoing_links))
        .route("/documents/search", get(search_documents))
        .with_state(ctx)
}
