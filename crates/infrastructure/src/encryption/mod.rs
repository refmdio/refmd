//! Encryption infrastructure implementations

pub mod device_key_repositories;
pub mod device_repository;
pub mod kek_rotation_completion_service;
pub mod pending_device_repository;
pub mod rotation_marking_service;
pub mod user_key_repositories;
pub mod workspace_key_repositories;

// Re-export repositories
pub use device_key_repositories::{
    PgDeviceEncryptedUMKRepository, PgDeviceEncryptedUMKRepositoryError,
    PgDeviceRevocationEventRepository, PgDeviceRevocationEventRepositoryError,
};
pub use device_repository::{PgDeviceRepository, PgDeviceRepositoryError};
pub use kek_rotation_completion_service::PgKekRotationCompletionService;
pub use pending_device_repository::{PgPendingDeviceRepository, PgPendingDeviceRepositoryError};
pub use rotation_marking_service::PgRotationMarkingService;
pub use user_key_repositories::{
    PgUserEncryptedIdentityKeyRepository, PgUserEncryptedIdentityKeyRepositoryError,
    PgUserEncryptedMasterKeyRepository, PgUserEncryptedMasterKeyRepositoryError,
    PgUserIdentityPublicKeyRepository, PgUserIdentityPublicKeyRepositoryError,
};
pub use workspace_key_repositories::{
    PgDocumentEncryptedKeyRepository, PgDocumentEncryptedKeyRepositoryError,
    PgWorkspaceEncryptedKeyRepository, PgWorkspaceEncryptedKeyRepositoryError,
    PgWorkspaceKekBackupRepository, PgWorkspaceKekBackupRepositoryError,
};
