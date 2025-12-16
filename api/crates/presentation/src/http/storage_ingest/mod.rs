mod handlers;
pub mod types;

use axum::{Router, routing::post};

use crate::context::AppContext;

pub use handlers::*;
pub use types::*;

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/storage/ingest", post(enqueue_ingest_events))
        .with_state(ctx)
}
