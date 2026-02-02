//! Application state with generics for dependency injection

use std::sync::Arc;
use application::domain::identity::{
    SessionRepository, UserRepository, UserSettingsRepository,
};

/// Application state holding repository implementations
#[derive(Clone)]
pub struct AppState<U, S, US>
where
    U: UserRepository + Send + Sync + 'static,
    S: SessionRepository + Send + Sync + 'static,
    US: UserSettingsRepository + Send + Sync + 'static,
{
    user_repo: Arc<U>,
    session_repo: Arc<S>,
    user_settings_repo: Arc<US>,
}

impl<U, S, US> AppState<U, S, US>
where
    U: UserRepository + Send + Sync + 'static,
    S: SessionRepository + Send + Sync + 'static,
    US: UserSettingsRepository + Send + Sync + 'static,
{
    pub fn new(user_repo: Arc<U>, session_repo: Arc<S>, user_settings_repo: Arc<US>) -> Self {
        Self {
            user_repo,
            session_repo,
            user_settings_repo,
        }
    }

    pub fn user_repo(&self) -> Arc<U> {
        Arc::clone(&self.user_repo)
    }

    pub fn session_repo(&self) -> Arc<S> {
        Arc::clone(&self.session_repo)
    }

    pub fn user_settings_repo(&self) -> Arc<US> {
        Arc::clone(&self.user_settings_repo)
    }
}
