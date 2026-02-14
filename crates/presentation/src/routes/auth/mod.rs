//! Authentication routes

mod login;
mod pop_challenge;
mod recovery;
mod register;
mod salt;
mod session;

// Re-export all public types for backward compatibility with OpenAPI paths
pub use login::*;
pub use pop_challenge::*;
pub use recovery::*;
pub use register::*;
pub use salt::*;
pub use session::*;

use axum::{Router, routing::{get, post}};
use tower_governor::GovernorLayer;

use crate::{
    AppState,
    rate_limit::{create_auth_rate_limit_config, create_register_rate_limit_config},
};

/// Session cookie name
pub const SESSION_COOKIE_NAME: &str = "refmd_session";

super::error_response_struct!(AuthErrorResponse, "invalid email");

/// KDF parameters response
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct KdfParamsResponse {
    /// Memory cost in KiB
    #[schema(example = 65536)]
    pub memory_cost: u32,
    /// Time cost (iterations)
    #[schema(example = 3)]
    pub time_cost: u32,
    /// Parallelism factor
    #[schema(example = 4)]
    pub parallelism: u32,
}

impl From<application::dto::KdfParamsDto> for KdfParamsResponse {
    fn from(params: application::dto::KdfParamsDto) -> Self {
        Self {
            memory_cost: params.memory_cost,
            time_cost: params.time_cost,
            parallelism: params.parallelism,
        }
    }
}

/// Build session cookie string
///
/// Note: Always set Expires attribute regardless of remember_me flag.
/// This ensures sessions persist for 24 hours (or 30 days for remember_me)
/// even when the browser is closed and reopened.
pub(crate) fn build_session_cookie(
    token: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
    secure: bool,
) -> String {
    let mut cookie = format!(
        "{}={}; Path=/api; HttpOnly; SameSite=Lax",
        SESSION_COOKIE_NAME, token
    );

    if secure {
        cookie.push_str("; Secure");
    }

    let expires = expires_at.format("%a, %d %b %Y %H:%M:%S GMT");
    cookie.push_str(&format!("; Expires={}", expires));

    cookie
}

/// Build cookie string to clear session
fn build_clear_cookie(secure: bool) -> String {
    let mut cookie = format!(
        "{}=; Path=/api; HttpOnly; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        SESSION_COOKIE_NAME
    );

    if secure {
        cookie.push_str("; Secure");
    }

    cookie
}

/// Create auth routes
pub fn routes(state: AppState) -> Result<Router, anyhow::Error> {
    // Rate limiting configs
    let register_rate_limit = create_register_rate_limit_config()?;
    let auth_rate_limit = create_auth_rate_limit_config()?;

    // Routes with stricter rate limiting (registration)
    let register_routes = Router::new()
        .route("/register", post(register))
        .layer(GovernorLayer {
            config: register_rate_limit,
        });

    // Routes with standard auth rate limiting (login, salt, recovery)
    let auth_rate_limited_routes = Router::new()
        .route("/salt", get(get_salt))
        .route("/login", post(login))
        .route("/recovery", get(get_recovery))
        .route("/recovery/challenge", post(create_recovery_challenge))
        .route("/recovery/session", post(create_recovery_session))
        .layer(GovernorLayer {
            config: auth_rate_limit,
        });

    // Routes without rate limiting (authenticated endpoints)
    let non_rate_limited_routes = Router::new()
        .route("/logout", post(logout))
        .route("/me", get(me))
        .route("/pop-challenge", post(create_pop_challenge));

    Ok(Router::new()
        .merge(register_routes)
        .merge(auth_rate_limited_routes)
        .merge(non_rate_limited_routes)
        .with_state(state))
}
