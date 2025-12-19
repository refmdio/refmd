mod handlers;
pub mod types;

use axum::{Router, routing::get};

use crate::context::AppContext;

pub use handlers::{get_user_shortcuts, update_user_shortcuts};
pub use types::*;

pub mod openapi {
    pub use super::handlers::*;
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route(
            "/me/shortcuts",
            get(get_user_shortcuts).put(update_user_shortcuts),
        )
        .with_state(ctx)
}
