mod active;
mod applicable;
mod core;
mod mounts;
pub mod types;
mod validation;

use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::context::AppContext;

pub use active::list_active_shares;
pub use applicable::list_applicable_shares;
pub use core::{create_share, delete_share, list_document_shares};
pub use mounts::{
    create_share_mount, delete_share_mount, list_share_mounts, materialize_folder_share,
};
pub use types::*;
pub use validation::{browse_share, validate_share_token};

pub mod openapi {
    pub use super::active::*;
    pub use super::applicable::*;
    pub use super::core::*;
    pub use super::mounts::*;
    pub use super::validation::*;
}

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
