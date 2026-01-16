//! E2EE migration HTTP module.

pub mod handlers;
pub mod types;

use axum::{routing::{get, post}, Router};

use crate::context::AppContext;

pub use handlers::{migrate, needs_migration, NeedsMigrationResponse};
pub use types::*;

pub mod openapi {
    pub use super::handlers::*;
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/me/encryption/migrate", post(handlers::migrate))
        .route("/me/encryption/needs-migration", get(handlers::needs_migration))
        .with_state(ctx)
}
