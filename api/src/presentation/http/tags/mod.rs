mod handlers;
pub mod types;

use axum::{Router, routing::get};

use crate::presentation::context::AppContext;

pub use handlers::*;
pub use types::*;

pub fn routes(ctx: AppContext) -> Router {
    Router::new().route("/tags", get(list_tags)).with_state(ctx)
}
