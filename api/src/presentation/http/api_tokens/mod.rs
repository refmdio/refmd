mod handlers;
pub mod types;

use axum::Router;
use axum::routing::{delete, get};

use crate::presentation::context::AppContext;

pub use handlers::*;
pub use types::*;

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route(
            "/me/api-tokens",
            get(list_api_tokens).post(create_api_token),
        )
        .route("/me/api-tokens/:id", delete(revoke_api_token))
        .with_state(ctx)
}
