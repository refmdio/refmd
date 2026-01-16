mod assets;
mod install;
mod kv;
mod manifest;
mod records;
pub mod types;
mod updates;
mod util;

use axum::{
    Router,
    routing::{get, patch, post},
};

use crate::context::AppContext;

pub use assets::get_plugin_asset;
pub use install::{install_from_url, uninstall};
pub use kv::{get_kv_value, put_kv_value};
pub use manifest::get_manifest;
pub use records::{create_record, delete_record, list_records, update_record};
pub use types::*;
pub use updates::sse_updates;

pub mod openapi {
    pub use super::assets::*;
    pub use super::install::*;
    pub use super::kv::*;
    pub use super::manifest::*;
    pub use super::records::*;
    pub use super::updates::*;
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        // Manifest for current user (stubbed)
        .route("/me/plugins/manifest", get(get_manifest))
        // SSE updates (stubbed)
        .route("/me/plugins/updates", get(sse_updates))
        .route("/me/plugins/install-from-url", post(install_from_url))
        .route("/me/plugins/uninstall", post(uninstall))
        // Generic records API
        .route(
            "/plugins/:plugin/docs/:doc_id/records/:kind",
            get(list_records).post(create_record),
        )
        .route(
            "/plugins/:plugin/records/:id",
            patch(update_record).delete(delete_record),
        )
        .route(
            "/plugins/:plugin/docs/:doc_id/kv/:key",
            get(get_kv_value).put(put_kv_value),
        )
        .route("/plugin-assets", get(get_plugin_asset))
        .with_state(ctx)
}
