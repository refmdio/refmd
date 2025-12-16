mod download;
mod serve;
pub mod types;
mod upload;

use axum::{
    Router,
    routing::{get, post},
};

use crate::presentation::context::AppContext;

pub use download::*;
pub use serve::*;
pub use types::*;
pub use upload::*;

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/files", post(upload_file))
        .route("/files/:id", get(get_file))
        .route("/files/documents/:filename", get(get_file_by_name))
        .with_state(ctx)
}
