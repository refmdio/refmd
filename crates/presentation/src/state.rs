//! Application state with generics for dependency injection

use crate::middleware::{ChallengeStore, RecoveryChallengeStore};
use application::domain::transfer_nonce::{TransferNonceStore, TransferStateStore};
use application::domain::document::{DocumentRepository, DocumentUpdateRepository};
use application::domain::encryption::{
    DeviceEncryptedUMKRepository, DeviceRepository, DeviceRevocationEventRepository,
    DocumentEncryptedKeyRepository, PendingDeviceRepository, UserEncryptedIdentityKeyRepository,
    UserEncryptedMasterKeyRepository, UserIdentityPublicKeyRepository,
    WorkspaceEncryptedKeyRepository, WorkspaceKekBackupRepository,
};
use application::domain::identity::{SessionRepository, UserRepository, UserSettingsRepository};
use application::domain::workspace::{
    WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRoleRepository,
};
use application::identity::RegistrationService;
use std::sync::Arc;

/// Type alias for dynamic ChallengeStore
pub type DynChallengeStore = Arc<dyn ChallengeStore>;

/// Type alias for dynamic RecoveryChallengeStore
pub type DynRecoveryChallengeStore = Arc<dyn RecoveryChallengeStore>;

/// Type alias for dynamic DeviceEventBus
/// Note: We use the DeviceEventBus trait which combines DeviceEventPublisher + DeviceEventSubscriber
pub type DynDeviceEventBus = Arc<dyn crate::events::DeviceEventBus>;

/// Type alias for dynamic TransferNonceStore
pub type DynTransferNonceStore = Arc<dyn TransferNonceStore>;

/// Type alias for dynamic TransferStateStore
pub type DynTransferStateStore = Arc<dyn TransferStateStore>;

/// A concrete error type that wraps a boxed error for object safety
/// This is needed because `Box<dyn Error>` doesn't implement `Error` (Sized requirement)
#[derive(Debug)]
pub struct BoxedError(pub Box<dyn std::error::Error + Send + Sync>);

impl std::fmt::Display for BoxedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for BoxedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

/// Type alias for dynamic DeviceRevocationEventRepository
pub type DynDeviceRevocationEventRepository =
    Arc<dyn DeviceRevocationEventRepository<Error = BoxedError>>;

/// Type alias for dynamic WorkspaceKekBackupRepository
pub type DynWorkspaceKekBackupRepository =
    Arc<dyn WorkspaceKekBackupRepository<Error = BoxedError>>;

/// Parameters for creating AppState
pub struct AppStateParams<
    U,
    S,
    US,
    UIP,
    UEM,
    UEI,
    WR,
    WMR,
    WRR,
    DR,
    DUR,
    WKR,
    DKR,
    RS,
    DER,
    PDR,
    UMKR,
> {
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
    pub document_update_repo: Arc<DUR>,
    pub workspace_key_repo: Arc<WKR>,
    pub document_key_repo: Arc<DKR>,
    pub registration_service: Arc<RS>,
    pub device_repo: Arc<DER>,
    pub pending_device_repo: Arc<PDR>,
    pub device_encrypted_umk_repo: Arc<UMKR>,
    /// Device revocation event repository for storing revocation signatures (dynamic dispatch)
    pub device_revocation_event_repo: DynDeviceRevocationEventRepository,
    /// Workspace KEK backup repository (dynamic dispatch)
    pub workspace_kek_backup_repo: DynWorkspaceKekBackupRepository,
    /// Device event bus for SSE notifications (dynamic dispatch)
    pub device_event_bus: DynDeviceEventBus,
    /// Challenge store for server-issued PoP challenges (dynamic dispatch)
    pub challenge_store: DynChallengeStore,
    /// Recovery challenge store for recovery session authentication (dynamic dispatch)
    pub recovery_challenge_store: DynRecoveryChallengeStore,
    /// Transfer nonce store for trust state transfer (dynamic dispatch)
    pub transfer_nonce_store: DynTransferNonceStore,
    /// Transfer state store for trust state transfer (dynamic dispatch)
    pub transfer_state_store: DynTransferStateStore,
    /// Server secret for dummy salt generation (prevents user enumeration)
    pub server_secret: [u8; 32],
    /// Whether to set Secure attribute on cookies (should be true in production)
    pub secure_cookies: bool,
    /// Whether cluster mode is enabled
    pub cluster_enabled: bool,
}

/// Application state holding repository implementations
#[derive(Clone)]
pub struct AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>
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
    DUR: DocumentUpdateRepository + Send + Sync + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + 'static,
    RS: RegistrationService + Send + Sync + 'static,
    DER: DeviceRepository + Send + Sync + 'static,
    PDR: PendingDeviceRepository + Send + Sync + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + 'static,
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
    document_update_repo: Arc<DUR>,
    workspace_key_repo: Arc<WKR>,
    document_key_repo: Arc<DKR>,
    registration_service: Arc<RS>,
    device_repo: Arc<DER>,
    pending_device_repo: Arc<PDR>,
    device_encrypted_umk_repo: Arc<UMKR>,
    /// Device revocation event repository for storing revocation signatures (dynamic dispatch)
    device_revocation_event_repo: DynDeviceRevocationEventRepository,
    /// Workspace KEK backup repository (dynamic dispatch)
    workspace_kek_backup_repo: DynWorkspaceKekBackupRepository,
    /// Device event bus for SSE notifications (dynamic dispatch)
    device_event_bus: DynDeviceEventBus,
    /// Challenge store for server-issued PoP challenges (dynamic dispatch)
    challenge_store: DynChallengeStore,
    /// Recovery challenge store for recovery session authentication (dynamic dispatch)
    recovery_challenge_store: DynRecoveryChallengeStore,
    /// Transfer nonce store for trust state transfer (dynamic dispatch)
    transfer_nonce_store: DynTransferNonceStore,
    /// Transfer state store for trust state transfer (dynamic dispatch)
    transfer_state_store: DynTransferStateStore,
    /// Server secret for dummy salt generation (prevents user enumeration)
    server_secret: Arc<[u8; 32]>,
    /// Whether to set Secure attribute on cookies (should be true in production)
    secure_cookies: bool,
    /// Whether cluster mode is enabled
    cluster_enabled: bool,
}

impl<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>
    AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>
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
    DUR: DocumentUpdateRepository + Send + Sync + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + 'static,
    RS: RegistrationService + Send + Sync + 'static,
    DER: DeviceRepository + Send + Sync + 'static,
    PDR: PendingDeviceRepository + Send + Sync + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + 'static,
{
    pub fn new(
        params: AppStateParams<
            U,
            S,
            US,
            UIP,
            UEM,
            UEI,
            WR,
            WMR,
            WRR,
            DR,
            DUR,
            WKR,
            DKR,
            RS,
            DER,
            PDR,
            UMKR,
        >,
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
            document_update_repo: params.document_update_repo,
            workspace_key_repo: params.workspace_key_repo,
            document_key_repo: params.document_key_repo,
            registration_service: params.registration_service,
            device_repo: params.device_repo,
            pending_device_repo: params.pending_device_repo,
            device_encrypted_umk_repo: params.device_encrypted_umk_repo,
            device_revocation_event_repo: params.device_revocation_event_repo,
            workspace_kek_backup_repo: params.workspace_kek_backup_repo,
            device_event_bus: params.device_event_bus,
            challenge_store: params.challenge_store,
            recovery_challenge_store: params.recovery_challenge_store,
            transfer_nonce_store: params.transfer_nonce_store,
            transfer_state_store: params.transfer_state_store,
            server_secret: Arc::new(params.server_secret),
            secure_cookies: params.secure_cookies,
            cluster_enabled: params.cluster_enabled,
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

    pub fn document_update_repo(&self) -> Arc<DUR> {
        Arc::clone(&self.document_update_repo)
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

    pub fn device_repo(&self) -> Arc<DER> {
        Arc::clone(&self.device_repo)
    }

    pub fn pending_device_repo(&self) -> Arc<PDR> {
        Arc::clone(&self.pending_device_repo)
    }

    pub fn device_encrypted_umk_repo(&self) -> Arc<UMKR> {
        Arc::clone(&self.device_encrypted_umk_repo)
    }

    pub fn device_revocation_event_repo(&self) -> DynDeviceRevocationEventRepository {
        Arc::clone(&self.device_revocation_event_repo)
    }

    pub fn workspace_kek_backup_repo(&self) -> DynWorkspaceKekBackupRepository {
        Arc::clone(&self.workspace_kek_backup_repo)
    }

    pub fn device_event_bus(&self) -> &DynDeviceEventBus {
        &self.device_event_bus
    }

    pub fn challenge_store(&self) -> DynChallengeStore {
        Arc::clone(&self.challenge_store)
    }

    pub fn recovery_challenge_store(&self) -> DynRecoveryChallengeStore {
        Arc::clone(&self.recovery_challenge_store)
    }

    pub fn transfer_nonce_store(&self) -> DynTransferNonceStore {
        Arc::clone(&self.transfer_nonce_store)
    }

    pub fn transfer_state_store(&self) -> DynTransferStateStore {
        Arc::clone(&self.transfer_state_store)
    }

    pub fn server_secret(&self) -> &[u8; 32] {
        &self.server_secret
    }

    /// Whether cookies should have the Secure attribute
    pub fn secure_cookies(&self) -> bool {
        self.secure_cookies
    }

    /// Whether cluster mode is enabled
    pub fn cluster_enabled(&self) -> bool {
        self.cluster_enabled
    }
}
