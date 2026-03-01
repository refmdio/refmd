//! Dynamic dispatch type aliases for all repositories and services

use application::types::{
    BoxedError, ChallengeStore, DeviceEncryptedUMKRepository, DeviceRepository,
    DeviceRevocationEventRepository, DocumentEncryptedKeyRepository, DocumentRepository,
    DocumentSnapshotRepository, DocumentUpdateRepository, PendingDeviceRepository,
    RecoveryChallengeStore, SessionRepository, TransferNonceStore, TransferStateStore,
    UserEncryptedIdentityKeyRepository, UserEncryptedMasterKeyRepository,
    UserIdentityPublicKeyRepository, UserRepository, UserSettingsRepository,
    WorkspaceEncryptedKeyRepository, WorkspaceInvitationRepository,
    WorkspaceKekBackupRepository, WorkspaceMemberRepository, WorkspaceRepository,
    WorkspaceRolePermissionRepository, WorkspaceRoleRepository,
};
use application::identity::RegistrationService;
use application::encryption::{KekRotationCompletionService, RotationMarkingService};
use application::workspace::{
    InvitationAcceptanceService, InvitationCreationService, MemberMutationService,
    RoleUpdateService, WorkspaceCreationService,
};
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
pub(crate) type DynWorkspaceRolePermissionRepository =
    Arc<dyn WorkspaceRolePermissionRepository<Error = BoxedError>>;
pub(crate) type DynWorkspaceInvitationRepository =
    Arc<dyn WorkspaceInvitationRepository<Error = BoxedError>>;

// Document repositories
pub(crate) type DynDocumentRepository = Arc<dyn DocumentRepository<Error = BoxedError>>;
pub(crate) type DynDocumentUpdateRepository =
    Arc<dyn DocumentUpdateRepository<Error = BoxedError>>;
pub(crate) type DynSnapshotRepository =
    Arc<dyn DocumentSnapshotRepository<Error = BoxedError>>;

// Services
pub(crate) type DynRegistrationService = Arc<dyn RegistrationService>;
pub(crate) type DynWorkspaceCreationService = Arc<dyn WorkspaceCreationService>;
pub(crate) type DynInvitationAcceptanceService = Arc<dyn InvitationAcceptanceService>;
pub(crate) type DynInvitationCreationService = Arc<dyn InvitationCreationService>;
pub(crate) type DynMemberMutationService = Arc<dyn MemberMutationService>;
pub(crate) type DynRoleUpdateService = Arc<dyn RoleUpdateService>;
pub(crate) type DynKekRotationCompletionService = Arc<dyn KekRotationCompletionService>;
pub(crate) type DynRotationMarkingService = Arc<dyn RotationMarkingService>;

// Infrastructure services (no Error associated type)
pub(crate) type DynChallengeStore = Arc<dyn ChallengeStore>;
pub(crate) type DynRecoveryChallengeStore = Arc<dyn RecoveryChallengeStore>;
pub(crate) type DynDeviceEventBus = Arc<dyn application::events::DeviceEventBus>;
pub(crate) type DynWorkspaceEventBus = Arc<dyn application::workspace_events::WorkspaceEventBus>;
pub(crate) type DynTransferNonceStore = Arc<dyn TransferNonceStore>;
pub(crate) type DynTransferStateStore = Arc<dyn TransferStateStore>;
