mod config;
mod proxy;
mod ssh_tunnel;
pub mod types;

use axum::{
    Router,
    routing::{get, options, post},
};

use crate::context::AppContext;

pub use config::{create_or_update_config, delete_config, get_config};
pub use types::*;

pub mod openapi {
    pub use super::config::*;
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route(
            "/git/config",
            get(get_config)
                .post(create_or_update_config)
                .delete(delete_config),
        )
        // Git HTTPS proxy for isomorphic-git
        .route(
            "/git/proxy/https/*path",
            options(proxy::proxy_git_https_options)
                .get(proxy::proxy_git_https)
                .post(proxy::proxy_git_https),
        )
        // Git SSH tunnel for isomorphic-git
        .route("/git/proxy/ssh", post(ssh_tunnel::tunnel_git_ssh))
        .with_state(ctx)
}
