mod handlers;
pub mod types;

use axum::{Router, routing::get};

use crate::context::AppContext;

pub use handlers::{get_document_tags, list_tags, update_document_tags};
pub use types::*;

pub mod openapi {
    pub use super::handlers::*;
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/tags", get(list_tags))
        .route(
            "/documents/:id/tags",
            get(get_document_tags).put(update_document_tags),
        )
        .with_state(ctx)
}
