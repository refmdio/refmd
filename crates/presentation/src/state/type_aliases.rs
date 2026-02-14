//! Dynamic dispatch type aliases for all repositories and services

use application::types::{
    BoxedError, ChallengeStore, DeviceEncryptedUMKRepository, DeviceRepository,
    DeviceRevocationEventRepository, DocumentEncryptedKeyRepository, DocumentRepository,
    DocumentUpdateRepository, PendingDeviceRepository, RecoveryChallengeStore, SessionRepository,
    TransferNonceStore, TransferStateStore, UserEncryptedIdentityKeyRepository,
    UserEncryptedMasterKeyRepository, UserIdentityPublicKeyRepository, UserRepository,
    UserSettingsRepository, WorkspaceEncryptedKeyRepository, WorkspaceKekBackupRepository,
    WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRoleRepository,
};
use application::identity::RegistrationService;
use std::sync::Arc;

// Identity repositories
pub(crate) type DynUserRepository = Arc<dyn UserRepository<Error = BoxedError>>;
pub(crate) type DynSessionRepository = Arc<dyn SessionRepository<Error = BoxedError>>;
pub(crate) type DynUserSettingsRepository = Arc<dyn UserSettingsRepository<Error = BoxedError>>;

// Encryption repositories
pub(crate) type DynUserIdentityPublicKeyRepository =
    Arc<dyn UserIdentityPublicKeyRepository<Error = BoxedError>>;
pub(crate) type DynUserEncryptedMasterKeyRepository =
    Arc<dyn UserEncryptedMasterKeyRepository<Error = BoxedError>>;
pub(crate) type DynUserEncryptedIdentityKeyRepository =
    Arc<dyn UserEncryptedIdentityKeyRepository<Error = BoxedError>>;
pub(crate) type DynDeviceRepository = Arc<dyn DeviceRepository<Error = BoxedError>>;
pub(crate) type DynPendingDeviceRepository = Arc<dyn PendingDeviceRepository<Error = BoxedError>>;
pub(crate) type DynDeviceEncryptedUMKRepository =
    Arc<dyn DeviceEncryptedUMKRepository<Error = BoxedError>>;
pub(crate) type DynDeviceRevocationEventRepository =
    Arc<dyn DeviceRevocationEventRepository<Error = BoxedError>>;
pub(crate) type DynWorkspaceEncryptedKeyRepository =
    Arc<dyn WorkspaceEncryptedKeyRepository<Error = BoxedError>>;
pub(crate) type DynDocumentEncryptedKeyRepository =
    Arc<dyn DocumentEncryptedKeyRepository<Error = BoxedError>>;
pub(crate) type DynWorkspaceKekBackupRepository =
    Arc<dyn WorkspaceKekBackupRepository<Error = BoxedError>>;

// Workspace repositories
pub(crate) type DynWorkspaceRepository = Arc<dyn WorkspaceRepository<Error = BoxedError>>;
pub(crate) type DynWorkspaceMemberRepository =
    Arc<dyn WorkspaceMemberRepository<Error = BoxedError>>;
pub(crate) type DynWorkspaceRoleRepository = Arc<dyn WorkspaceRoleRepository<Error = BoxedError>>;

// Document repositories
pub(crate) type DynDocumentRepository = Arc<dyn DocumentRepository<Error = BoxedError>>;
pub(crate) type DynDocumentUpdateRepository =
    Arc<dyn DocumentUpdateRepository<Error = BoxedError>>;

// Services
pub(crate) type DynRegistrationService = Arc<dyn RegistrationService>;

// Infrastructure services (no Error associated type)
pub(crate) type DynChallengeStore = Arc<dyn ChallengeStore>;
pub(crate) type DynRecoveryChallengeStore = Arc<dyn RecoveryChallengeStore>;
pub(crate) type DynDeviceEventBus = Arc<dyn application::events::DeviceEventBus>;
pub(crate) type DynTransferNonceStore = Arc<dyn TransferNonceStore>;
pub(crate) type DynTransferStateStore = Arc<dyn TransferStateStore>;
