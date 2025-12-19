mod handlers;
pub mod types;
mod user_scope;

use axum::{Router, routing::post};

use crate::context::AppContext;

pub use handlers::{render_markdown, render_markdown_many};
pub use types::*;

pub mod openapi {
    pub use super::handlers::*;
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/markdown/render", post(render_markdown))
        .route("/markdown/render-many", post(render_markdown_many))
        .with_state(ctx)
}
