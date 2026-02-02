//! Application state with generics for dependency injection

use std::sync::Arc;
use application::domain::encryption::{
    UserEncryptedIdentityKeyRepository, UserEncryptedMasterKeyRepository,
    UserIdentityPublicKeyRepository,
};
use application::domain::identity::{SessionRepository, UserRepository, UserSettingsRepository};

/// Application state holding repository implementations
#[derive(Clone)]
pub struct AppState<U, S, US, UIP, UEM, UEI>
where
    U: UserRepository + Send + Sync + 'static,
    S: SessionRepository + Send + Sync + 'static,
    US: UserSettingsRepository + Send + Sync + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + 'static,
{
    user_repo: Arc<U>,
    session_repo: Arc<S>,
    user_settings_repo: Arc<US>,
    user_identity_public_key_repo: Arc<UIP>,
    user_encrypted_master_key_repo: Arc<UEM>,
    user_encrypted_identity_key_repo: Arc<UEI>,
    /// Server secret for dummy salt generation (prevents user enumeration)
    server_secret: Arc<[u8; 32]>,
    /// Whether to set Secure attribute on cookies (should be true in production)
    secure_cookies: bool,
}

impl<U, S, US, UIP, UEM, UEI> AppState<U, S, US, UIP, UEM, UEI>
where
    U: UserRepository + Send + Sync + 'static,
    S: SessionRepository + Send + Sync + 'static,
    US: UserSettingsRepository + Send + Sync + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + 'static,
{
    pub fn new(
        user_repo: Arc<U>,
        session_repo: Arc<S>,
        user_settings_repo: Arc<US>,
        user_identity_public_key_repo: Arc<UIP>,
        user_encrypted_master_key_repo: Arc<UEM>,
        user_encrypted_identity_key_repo: Arc<UEI>,
        server_secret: [u8; 32],
        secure_cookies: bool,
    ) -> Self {
        Self {
            user_repo,
            session_repo,
            user_settings_repo,
            user_identity_public_key_repo,
            user_encrypted_master_key_repo,
            user_encrypted_identity_key_repo,
            server_secret: Arc::new(server_secret),
            secure_cookies,
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

    pub fn user_identity_public_key_repo(&self) -> Arc<UIP> {
        Arc::clone(&self.user_identity_public_key_repo)
    }

    pub fn user_encrypted_master_key_repo(&self) -> Arc<UEM> {
        Arc::clone(&self.user_encrypted_master_key_repo)
    }

    pub fn user_encrypted_identity_key_repo(&self) -> Arc<UEI> {
        Arc::clone(&self.user_encrypted_identity_key_repo)
    }

    pub fn server_secret(&self) -> &[u8; 32] {
        &self.server_secret
    }

    /// Whether cookies should have the Secure attribute
    pub fn secure_cookies(&self) -> bool {
        self.secure_cookies
    }
}
