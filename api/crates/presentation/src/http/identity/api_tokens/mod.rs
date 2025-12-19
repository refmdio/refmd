mod handlers;
pub mod types;

use axum::Router;
use axum::routing::{delete, get};

use crate::context::AppContext;

pub use handlers::{create_api_token, list_api_tokens, revoke_api_token};
pub use types::*;

pub mod openapi {
    pub use super::handlers::*;
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route(
            "/me/api-tokens",
            get(list_api_tokens).post(create_api_token),
        )
        .route("/me/api-tokens/:id", delete(revoke_api_token))
        .with_state(ctx)
}
