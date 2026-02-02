//! Application state with generics for dependency injection

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
use std::sync::Arc;

/// Parameters for creating AppState
pub struct AppStateParams<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS> {
    pub user_repo: Arc<U>,
    pub session_repo: Arc<S>,
    pub user_settings_repo: Arc<US>,
    pub user_identity_public_key_repo: Arc<UIP>,
    pub user_encrypted_master_key_repo: Arc<UEM>,
    pub user_encrypted_identity_key_repo: Arc<UEI>,
    pub workspace_repo: Arc<WR>,
    pub workspace_member_repo: Arc<WMR>,
    pub workspace_role_repo: Arc<WRR>,
    pub document_repo: Arc<DR>,
    pub workspace_key_repo: Arc<WKR>,
    pub document_key_repo: Arc<DKR>,
    pub registration_service: Arc<RS>,
    /// Server secret for dummy salt generation (prevents user enumeration)
    pub server_secret: [u8; 32],
    /// Whether to set Secure attribute on cookies (should be true in production)
    pub secure_cookies: bool,
}

/// Application state holding repository implementations
#[derive(Clone)]
pub struct AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>
where
    U: UserRepository + Send + Sync + 'static,
    S: SessionRepository + Send + Sync + 'static,
    US: UserSettingsRepository + Send + Sync + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + 'static,
    WR: WorkspaceRepository + Send + Sync + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + 'static,
    DR: DocumentRepository + Send + Sync + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + 'static,
    RS: RegistrationService + Send + Sync + 'static,
{
    user_repo: Arc<U>,
    session_repo: Arc<S>,
    user_settings_repo: Arc<US>,
    user_identity_public_key_repo: Arc<UIP>,
    user_encrypted_master_key_repo: Arc<UEM>,
    user_encrypted_identity_key_repo: Arc<UEI>,
    workspace_repo: Arc<WR>,
    workspace_member_repo: Arc<WMR>,
    workspace_role_repo: Arc<WRR>,
    document_repo: Arc<DR>,
    workspace_key_repo: Arc<WKR>,
    document_key_repo: Arc<DKR>,
    registration_service: Arc<RS>,
    /// Server secret for dummy salt generation (prevents user enumeration)
    server_secret: Arc<[u8; 32]>,
    /// Whether to set Secure attribute on cookies (should be true in production)
    secure_cookies: bool,
}

impl<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>
    AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>
where
    U: UserRepository + Send + Sync + 'static,
    S: SessionRepository + Send + Sync + 'static,
    US: UserSettingsRepository + Send + Sync + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + 'static,
    WR: WorkspaceRepository + Send + Sync + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + 'static,
    DR: DocumentRepository + Send + Sync + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + 'static,
    RS: RegistrationService + Send + Sync + 'static,
{
    pub fn new(
        params: AppStateParams<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>,
    ) -> Self {
        Self {
            user_repo: params.user_repo,
            session_repo: params.session_repo,
            user_settings_repo: params.user_settings_repo,
            user_identity_public_key_repo: params.user_identity_public_key_repo,
            user_encrypted_master_key_repo: params.user_encrypted_master_key_repo,
            user_encrypted_identity_key_repo: params.user_encrypted_identity_key_repo,
            workspace_repo: params.workspace_repo,
            workspace_member_repo: params.workspace_member_repo,
            workspace_role_repo: params.workspace_role_repo,
            document_repo: params.document_repo,
            workspace_key_repo: params.workspace_key_repo,
            document_key_repo: params.document_key_repo,
            registration_service: params.registration_service,
            server_secret: Arc::new(params.server_secret),
            secure_cookies: params.secure_cookies,
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

    pub fn workspace_repo(&self) -> Arc<WR> {
        Arc::clone(&self.workspace_repo)
    }

    pub fn workspace_member_repo(&self) -> Arc<WMR> {
        Arc::clone(&self.workspace_member_repo)
    }

    pub fn workspace_role_repo(&self) -> Arc<WRR> {
        Arc::clone(&self.workspace_role_repo)
    }

    pub fn document_repo(&self) -> Arc<DR> {
        Arc::clone(&self.document_repo)
    }

    pub fn workspace_key_repo(&self) -> Arc<WKR> {
        Arc::clone(&self.workspace_key_repo)
    }

    pub fn document_key_repo(&self) -> Arc<DKR> {
        Arc::clone(&self.document_key_repo)
    }

    pub fn registration_service(&self) -> Arc<RS> {
        Arc::clone(&self.registration_service)
    }

    pub fn server_secret(&self) -> &[u8; 32] {
        &self.server_secret
    }

    /// Whether cookies should have the Secure attribute
    pub fn secure_cookies(&self) -> bool {
        self.secure_cookies
    }
}
