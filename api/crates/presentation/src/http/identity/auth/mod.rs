pub mod middleware;
mod types;

pub use types::*;

mod cookies;
mod handlers;
mod routes;
mod security;

pub mod request_status {
    pub use super::middleware::{mark_token_expired, middleware};
}

pub use crate::security::token::{AccessTokenOverride, Bearer};

pub use handlers::{
    delete_account, list_oauth_providers, list_sessions, login, logout, me, oauth_login,
    oauth_state, refresh_session, register, revoke_session,
};

// `utoipa::OpenApi(paths(...))` needs the generated `__path_*` items to be visible from the module
// path referenced in `paths(...)`. Keep those under `auth::openapi` so we don't leak `__path_*`
// from the main `auth` module API.
pub mod openapi {
    pub use super::handlers::*;
}
pub use routes::routes;
pub use security::{
    refresh_middleware, resolve_actor_from_parts, resolve_actor_from_token_str,
    validate_bearer_public, validate_bearer_str,
};

pub(crate) use cookies::{
    apply_session_cookies, clear_auth_cookies, extract_client_ip, extract_refresh_token,
    extract_user_agent,
};
pub(crate) use security::{map_auth_error, validate_bearer};

#[cfg(test)]
mod tests;
