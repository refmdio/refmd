mod download;
mod list;
mod serve;
pub mod types;
mod upload;

use axum::{
    Router,
    routing::{get, post},
};

use crate::context::AppContext;

pub use download::get_file;
pub use list::list_files;
pub use serve::serve_upload;
pub use types::*;
pub use upload::upload_file;

pub mod openapi {
    pub use super::download::__path_get_file;
    pub use super::list::__path_list_files;
    pub use super::upload::__path_upload_file;
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/documents/:doc_id/files", post(upload_file).get(list_files))
        .route("/files/:id", get(get_file))
        .with_state(ctx)
}
