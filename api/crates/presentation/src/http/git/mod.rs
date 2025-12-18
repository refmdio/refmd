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

pub use config::{create_or_update_config, delete_config, get_config};
pub use ignore::{
    add_gitignore_patterns, check_path_ignored, get_gitignore_patterns, ignore_document,
    ignore_folder,
};
pub use pull::{
    finalize_pull_session, get_pull_session, pull_repository, resolve_pull_session,
    start_pull_session,
};
pub use status::{get_changes, get_commit_diff, get_history, get_status, get_working_diff};
pub use sync::{deinit_repository, import_repository, init_repository, sync_now};
pub use types::*;

pub mod openapi {
    pub use super::config::*;
    pub use super::ignore::*;
    pub use super::pull::*;
    pub use super::status::*;
    pub use super::sync::*;
}

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
