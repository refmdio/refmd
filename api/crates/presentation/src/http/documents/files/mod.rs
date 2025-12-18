mod download;
mod serve;
pub mod types;
mod upload;

use axum::{
    Router,
    routing::{get, post},
};

use crate::context::AppContext;

pub use download::{get_file, get_file_by_name};
pub use serve::serve_upload;
pub use types::*;
pub use upload::upload_file;

pub mod openapi {
    pub use super::download::*;
    pub use super::upload::*;
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/files", post(upload_file))
        .route("/files/:id", get(get_file))
        .route("/files/documents/:filename", get(get_file_by_name))
        .with_state(ctx)
}
