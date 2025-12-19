use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::context::AppContext;

use super::handlers::{
    delete_account, list_oauth_providers, list_sessions, login, logout, me, oauth_login,
    oauth_state, refresh_session, register, revoke_session,
};

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/oauth/:provider/state", post(oauth_state))
        .route("/oauth/:provider", post(oauth_login))
        .route("/providers", get(list_oauth_providers))
        .route("/logout", post(logout))
        .route("/refresh", post(refresh_session))
        .route("/sessions", get(list_sessions))
        .route("/sessions/:id", delete(revoke_session))
        .route("/me", get(me).delete(delete_account))
        .with_state(ctx)
}
