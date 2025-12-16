mod handlers;
pub mod types;

use axum::{routing::get, Router};

use crate::presentation::context::AppContext;

pub use handlers::*;
pub use types::*;

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route(
            "/me/shortcuts",
            get(get_user_shortcuts).put(update_user_shortcuts),
        )
        .with_state(ctx)
}
