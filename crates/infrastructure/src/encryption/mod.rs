//! Encryption infrastructure implementations

pub mod device_key_repositories;
pub mod device_repository;
pub mod pending_device_repository;
pub mod user_key_repositories;
pub mod workspace_key_repositories;

// Re-export repositories
pub use device_key_repositories::{
    PgDeviceEncryptedUMKRepository, PgDeviceEncryptedUMKRepositoryError,
    PgDeviceRevocationEventRepository, PgDeviceRevocationEventRepositoryError,
};
pub use device_repository::{PgDeviceRepository, PgDeviceRepositoryError};
pub use pending_device_repository::{PgPendingDeviceRepository, PgPendingDeviceRepositoryError};
pub use user_key_repositories::{
    PgUserEncryptedIdentityKeyRepository, PgUserEncryptedIdentityKeyRepositoryError,
    PgUserEncryptedMasterKeyRepository, PgUserEncryptedMasterKeyRepositoryError,
    PgUserIdentityPublicKeyRepository, PgUserIdentityPublicKeyRepositoryError,
};
pub use workspace_key_repositories::{
    PgDocumentEncryptedKeyRepository, PgDocumentEncryptedKeyRepositoryError,
    PgWorkspaceEncryptedKeyRepository, PgWorkspaceEncryptedKeyRepositoryError,
};
