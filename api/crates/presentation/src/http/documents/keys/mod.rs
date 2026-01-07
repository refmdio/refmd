mod handlers;
pub mod types;

use axum::routing::{get, post};
use axum::Router;

use crate::context::AppContext;

pub use handlers::{
    get_document_key, get_share_key, get_share_salt, rotate_document_key, store_document_key,
    store_password_protected_share_key, store_share_key,
};
pub use types::*;

pub mod openapi {
    pub use super::handlers::*;
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        // Document key endpoints
        .route(
            "/documents/:id/keys",
            get(get_document_key).post(store_document_key),
        )
        .route("/documents/:id/keys/rotate", post(rotate_document_key))
        // Share key endpoints
        .route(
            "/shares/:id/keys",
            get(get_share_key).post(store_share_key),
        )
        .route(
            "/shares/:id/keys/password-protected",
            post(store_password_protected_share_key),
        )
        .route("/shares/:id/salt", get(get_share_salt))
        .with_state(ctx)
}
