//! API routes

pub mod auth;
pub mod document;
pub mod encryption;
pub mod workspace;

use crate::AppState;
use application::domain::document::DocumentRepository;
use application::domain::encryption::{
    DocumentEncryptedKeyRepository, UserEncryptedIdentityKeyRepository,
    UserEncryptedMasterKeyRepository, UserIdentityPublicKeyRepository,
    WorkspaceEncryptedKeyRepository,
};
use application::domain::identity::{SessionRepository, UserRepository, UserSettingsRepository};
use application::domain::workspace::{
    WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRoleRepository,
};
use application::identity::RegistrationService;
use axum::Router;

/// Create all API routes
pub fn create_routes<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>(
    state: AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>,
) -> Router
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    Router::new().nest("/api", api_routes(state))
}

fn api_routes<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>(
    state: AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>,
) -> Router
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    Router::new()
        .nest("/auth", auth::routes(state.clone()))
        .nest("/workspaces", workspace::routes(state.clone()))
        .nest("/documents", document::routes(state.clone()))
        .nest("/encryption", encryption::routes(state))
}
