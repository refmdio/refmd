//! Encryption domain
//!
//! Manages cryptographic keys for users, workspaces, and documents.

pub mod device;
pub mod device_keys;
pub mod repository;
pub mod user_keys;
pub mod value_objects;
pub mod workspace_keys;

// Re-export commonly used types
pub use device::{Device, PendingDevice};
pub use device_keys::{DeviceEncryptedUMK, DeviceRevocationEvent};
pub use repository::{
    DeviceEncryptedUMKRepository, DeviceRepository, DeviceRevocationEventRepository,
    DocumentEncryptedKeyRepository, PendingDeviceRepository, UserEncryptedIdentityKeyRepository,
    UserEncryptedMasterKeyRepository, UserIdentityPublicKeyRepository,
    WorkspaceEncryptedKeyRepository,
};
pub use user_keys::{UserEncryptedIdentityKey, UserEncryptedMasterKey, UserIdentityPublicKey};
pub use value_objects::{
    AuthType, AuthTypeError, DeviceId, DeviceType, DeviceTypeError, EncryptedData, KdfParams,
    KdfType, KdfTypeError, KeyVersion, PublicKeyPair,
};
pub use workspace_keys::{DocumentEncryptedKey, WorkspaceEncryptedKey};
// WorkspaceId and DocumentId are defined in their respective domains, re-export for convenience
pub use crate::document::DocumentId;
pub use crate::workspace::WorkspaceId;
