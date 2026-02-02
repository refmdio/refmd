//! API routes

pub mod users;

use axum::Router;
use application::domain::identity::{
    SessionRepository, UserRepository, UserSettingsRepository,
};
use crate::AppState;

/// Create all API routes
pub fn create_routes<U, S, US>(state: AppState<U, S, US>) -> Router
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
{
    Router::new().nest("/api", api_routes(state))
}

fn api_routes<U, S, US>(state: AppState<U, S, US>) -> Router
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
{
    Router::new().nest("/users", users::routes(state))
}
