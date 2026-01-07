pub mod files;
mod handlers;
pub mod keys;
pub mod publishing;
pub mod sharing;
pub mod tagging;
pub mod types;

use axum::{
    Router,
    routing::{get, post},
};

use crate::context::AppContext;

pub use handlers::{
    archive_document, create_document, delete_document, download_document,
    download_document_snapshot, duplicate_document, get_backlinks, get_document,
    get_document_content, get_document_snapshot_diff, get_outgoing_links, list_document_snapshots,
    list_documents, patch_document_content, restore_document_snapshot, search_documents,
    unarchive_document, update_document, update_document_content,
};
pub use types::*;

pub mod openapi {
    pub use super::handlers::*;
}

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
