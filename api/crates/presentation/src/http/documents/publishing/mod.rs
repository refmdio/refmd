mod handlers;
pub mod types;

use axum::Router;
use axum::routing::{get, post};

use crate::context::AppContext;

pub use handlers::{
    get_public_by_workspace_and_id, get_public_content_by_workspace_and_id, get_public_file,
    get_publish_status, list_public_files, list_workspace_public_documents, publish_document,
    unpublish_document, update_publish_settings, upload_public_file,
};
pub use types::*;

pub mod openapi {
    pub use super::handlers::*;
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route(
            "/documents/:id",
            post(publish_document)
                .delete(unpublish_document)
                .get(get_publish_status)
                .patch(update_publish_settings),
        )
        .route("/documents/:id/files/:file_id", post(upload_public_file))
        .route("/workspaces/:slug", get(list_workspace_public_documents))
        .route("/workspaces/:slug/:id", get(get_public_by_workspace_and_id))
        .route(
            "/workspaces/:slug/:id/content",
            get(get_public_content_by_workspace_and_id),
        )
        .route("/workspaces/:slug/:id/files", get(list_public_files))
        .route("/workspaces/:slug/:id/files/:file_id", get(get_public_file))
        // legacy aliases
        .route("/users/:slug", get(list_workspace_public_documents))
        .route("/users/:slug/:id", get(get_public_by_workspace_and_id))
        .route(
            "/users/:slug/:id/content",
            get(get_public_content_by_workspace_and_id),
        )
        .with_state(ctx)
}
