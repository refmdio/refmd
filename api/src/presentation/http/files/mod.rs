mod download;
mod serve;
mod upload;
pub mod types;

use axum::{routing::{get, post}, Router};

use crate::presentation::context::AppContext;

pub use download::*;
pub use serve::*;
pub use upload::*;
pub use types::*;

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/files", post(upload_file))
        .route("/files/:id", get(get_file))
        .route("/files/documents/:filename", get(get_file_by_name))
        .with_state(ctx)
}
