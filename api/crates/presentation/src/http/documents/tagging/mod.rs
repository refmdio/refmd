mod handlers;
pub mod types;

use axum::{Router, routing::get};

use crate::context::AppContext;

pub use handlers::list_tags;
pub use types::*;

pub mod openapi {
    pub use super::handlers::*;
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new().route("/tags", get(list_tags)).with_state(ctx)
}
