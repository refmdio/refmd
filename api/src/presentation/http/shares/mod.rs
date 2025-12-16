mod active;
mod applicable;
mod core;
mod mounts;
mod validation;
pub mod types;

use axum::{routing::{delete, get, post}, Router};

use crate::presentation::context::AppContext;

pub use active::*;
pub use applicable::*;
pub use core::*;
pub use mounts::*;
pub use validation::*;
pub use types::*;

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/shares", post(create_share))
        .route(
            "/shares/mounts",
            post(create_share_mount).get(list_share_mounts),
        )
        .route("/shares/browse", get(browse_share))
        .route("/shares/validate", get(validate_share_token))
        .route("/shares/documents/:id", get(list_document_shares))
        .route("/shares/applicable", get(list_applicable_shares))
        .route(
            "/shares/folders/:token/materialize",
            post(materialize_folder_share),
        )
        .route("/shares/active", get(list_active_shares))
        .route("/shares/mounts/:id", delete(delete_share_mount))
        .route("/shares/:token", delete(delete_share))
        .with_state(ctx)
}
