mod config;
mod ignore;
mod pull;
mod status;
mod sync;
pub mod types;

use axum::{
    Router,
    routing::{get, post},
};

use crate::context::AppContext;

// Re-export handlers and types so OpenAPI derives continue to work.
pub use config::*;
pub use ignore::*;
pub use pull::*;
pub use status::*;
pub use sync::*;
pub use types::*;

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route(
            "/git/config",
            get(get_config)
                .post(create_or_update_config)
                .delete(delete_config),
        )
        .route("/git/status", get(get_status))
        .route("/git/changes", get(get_changes))
        .route("/git/history", get(get_history))
        .route("/git/diff/working", get(get_working_diff))
        .route("/git/diff/commits/:from/:to", get(get_commit_diff))
        .route("/git/sync", post(sync_now))
        .route("/git/import", post(import_repository))
        .route("/git/pull", post(pull_repository))
        .route("/git/pull/start", post(start_pull_session))
        .route("/git/pull/session/:id", get(get_pull_session))
        .route("/git/pull/session/:id/resolve", post(resolve_pull_session))
        .route(
            "/git/pull/session/:id/finalize",
            post(finalize_pull_session),
        )
        .route("/git/init", post(init_repository))
        .route("/git/deinit", post(deinit_repository))
        .route("/git/ignore/doc/:id", post(ignore_document))
        .route("/git/ignore/folder/:id", post(ignore_folder))
        .route(
            "/git/gitignore/patterns",
            get(get_gitignore_patterns).post(add_gitignore_patterns),
        )
        .route("/git/gitignore/check", post(check_path_ignored))
        .with_state(ctx)
}
