mod handlers;
pub mod types;

use axum::Router;
use axum::routing::{get, post};

use crate::presentation::context::AppContext;

pub use handlers::*;
pub use types::*;

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route(
            "/documents/:id",
            post(publish_document)
                .delete(unpublish_document)
                .get(get_publish_status),
        )
        .route("/workspaces/:slug", get(list_workspace_public_documents))
        .route("/workspaces/:slug/:id", get(get_public_by_workspace_and_id))
        .route(
            "/workspaces/:slug/:id/content",
            get(get_public_content_by_workspace_and_id),
        )
        // legacy aliases
        .route("/users/:slug", get(list_workspace_public_documents))
        .route("/users/:slug/:id", get(get_public_by_workspace_and_id))
        .route(
            "/users/:slug/:id/content",
            get(get_public_content_by_workspace_and_id),
        )
        .with_state(ctx)
}
