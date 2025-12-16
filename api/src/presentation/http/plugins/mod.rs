mod assets;
mod exec;
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

use crate::presentation::context::AppContext;

pub use assets::*;
pub use exec::*;
pub use install::*;
pub use kv::*;
pub use manifest::*;
pub use records::*;
pub use types::*;
pub use updates::*;

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        // Manifest for current user (stubbed)
        .route("/me/plugins/manifest", get(get_manifest))
        // SSE updates (stubbed)
        .route("/me/plugins/updates", get(sse_updates))
        // Generic exec endpoint
        .route("/plugins/:plugin/exec/:action", post(exec_action))
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
