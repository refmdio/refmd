//! Facade re-exports of domain types for use by outer layers.
//!
//! This module acts as a **facade** (not a leaky abstraction): outer layers
//! (presentation, server) import domain types exclusively through here,
//! keeping the domain crate an internal dependency of the application layer.
//! If domain types are reorganised, only this file needs updating.

// =============================================================================
// SafeMessage: trait for user-safe error messages
// =============================================================================

/// Trait for errors that produce user-safe messages to prevent information leakage.
pub trait SafeMessage {
    fn safe_message(&self) -> &'static str;
}

// =============================================================================
// BoxedError: concrete error type for object-safe trait objects
// =============================================================================

/// A concrete error type that wraps a boxed error for object safety.
/// This is needed because `Box<dyn Error>` doesn't implement `Error` (Sized requirement).
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

// =============================================================================
// AppError: trait for application-layer error classification
// =============================================================================

/// Application error classification (transport-agnostic).
///
/// Defines **domain-semantic** error categories that outer layers map
/// to transport-specific responses. The categories describe _what happened_
/// from a business perspective, not _how_ to respond over the wire.
///
/// | Category            | Semantic meaning                      | Example HTTP mapping |
/// |---------------------|---------------------------------------|---------------------|
/// | `not_found`         | Requested resource does not exist     | 404                 |
/// | `access_denied`     | Caller lacks permission               | 403                 |
/// | `invalid_input`     | Input violates business rules         | 400                 |
/// | `conflict`          | Operation conflicts with current state| 409                 |
/// | `unauthenticated`   | Caller identity is unknown            | 401                 |
/// | `gone`              | Resource existed but was removed       | 410                 |
pub trait AppError: std::error::Error {
    fn is_not_found(&self) -> bool {
        false
    }
    fn is_access_denied(&self) -> bool {
        false
    }
    fn is_invalid_input(&self) -> bool {
        false
    }
    fn is_conflict(&self) -> bool {
        false
    }
    fn is_unauthenticated(&self) -> bool {
        false
    }
    fn is_gone(&self) -> bool {
        false
    }
}

/// Generate an `impl AppError for ErrorType { ... }` block declaratively.
///
/// Reduces boilerplate for the common pattern where each `AppError` method
/// is implemented as a `matches!()` expression on a subset of variants.
///
/// # Usage
///
/// Non-generic error type:
/// ```ignore
/// impl_app_error!(MyError,
///     not_found: [MyError::NotFound],
///     access_denied: [MyError::Forbidden],
/// );
/// ```
///
/// Generic error type — wrap generics in `[...]`:
/// ```ignore
/// impl_app_error!([DR: std::error::Error, MR: std::error::Error] MyError<DR, MR>,
///     not_found: [MyError::NotFound],
/// );
/// ```
///
/// Only categories with variants need to be listed; unlisted categories
/// default to `false` via the trait defaults.
macro_rules! impl_app_error {
    // Generic variant: [T: Bound, U: Bound] Type<T, U>
    // Must come before non-generic to avoid `[...]` being parsed as type.
    ([$($gen:tt)*] $err_type:ty,
        $(not_found: [$($nf:pat),+ $(,)?] $(,)?)?
        $(access_denied: [$($ad:pat),+ $(,)?] $(,)?)?
        $(invalid_input: [$($ii:pat),+ $(,)?] $(,)?)?
        $(conflict: [$($cf:pat),+ $(,)?] $(,)?)?
        $(unauthenticated: [$($ua:pat),+ $(,)?] $(,)?)?
        $(gone: [$($gn:pat),+ $(,)?] $(,)?)?
    ) => {
        impl<$($gen)*> crate::types::AppError for $err_type {
            $(
                fn is_not_found(&self) -> bool {
                    matches!(self, $($nf)|+)
                }
            )?
            $(
                fn is_access_denied(&self) -> bool {
                    matches!(self, $($ad)|+)
                }
            )?
            $(
                fn is_invalid_input(&self) -> bool {
                    matches!(self, $($ii)|+)
                }
            )?
            $(
                fn is_conflict(&self) -> bool {
                    matches!(self, $($cf)|+)
                }
            )?
            $(
                fn is_unauthenticated(&self) -> bool {
                    matches!(self, $($ua)|+)
                }
            )?
            $(
                fn is_gone(&self) -> bool {
                    matches!(self, $($gn)|+)
                }
            )?
        }
    };
    // Non-generic variant
    ($err_type:ty,
        $(not_found: [$($nf:pat),+ $(,)?] $(,)?)?
        $(access_denied: [$($ad:pat),+ $(,)?] $(,)?)?
        $(invalid_input: [$($ii:pat),+ $(,)?] $(,)?)?
        $(conflict: [$($cf:pat),+ $(,)?] $(,)?)?
        $(unauthenticated: [$($ua:pat),+ $(,)?] $(,)?)?
        $(gone: [$($gn:pat),+ $(,)?] $(,)?)?
    ) => {
        impl crate::types::AppError for $err_type {
            $(
                fn is_not_found(&self) -> bool {
                    matches!(self, $($nf)|+)
                }
            )?
            $(
                fn is_access_denied(&self) -> bool {
                    matches!(self, $($ad)|+)
                }
            )?
            $(
                fn is_invalid_input(&self) -> bool {
                    matches!(self, $($ii)|+)
                }
            )?
            $(
                fn is_conflict(&self) -> bool {
                    matches!(self, $($cf)|+)
                }
            )?
            $(
                fn is_unauthenticated(&self) -> bool {
                    matches!(self, $($ua)|+)
                }
            )?
            $(
                fn is_gone(&self) -> bool {
                    matches!(self, $($gn)|+)
                }
            )?
        }
    };
}

pub(crate) use impl_app_error;

// Domain crypto validation (re-exported for presentation layer)
pub use domain::crypto_validation;

// ID types
pub use domain::document::DocumentId;
pub use domain::encryption::{DeviceId, DeviceType};
pub use domain::identity::{SessionId, UserId};
pub use domain::workspace::{RoleId, WorkspaceId};

// Repository traits
pub use domain::document::{DocumentRepository, DocumentUpdateRepository};
pub use domain::encryption::{
    DeviceEncryptedUMKRepository, DeviceRepository, DeviceRevocationEventRepository,
    DocumentEncryptedKeyRepository, PendingDeviceRepository, UserEncryptedIdentityKeyRepository,
    UserEncryptedMasterKeyRepository, UserIdentityPublicKeyRepository,
    WorkspaceEncryptedKeyRepository, WorkspaceKekBackupRepository,
};
pub use domain::identity::{SessionRepository, UserRepository, UserSettingsRepository};
pub use domain::workspace::{
    WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRoleRepository,
};

// Entity types
pub use domain::document::{Document, DocumentUpdate};
pub use domain::encryption::{
    Device, DeviceEncryptedUMK, DeviceRevocationEvent, DocumentEncryptedKey, PendingDevice,
    UserEncryptedIdentityKey, UserEncryptedMasterKey, UserIdentityPublicKey,
    WorkspaceEncryptedKey, WorkspaceKekBackup,
};
pub use domain::identity::{Email, Session, User, UserSettings};
pub use domain::workspace::{Slug, Workspace, WorkspaceMember, WorkspaceRole};

// Store traits
pub use domain::pop::{ChallengeError, ChallengeStore};
pub use domain::recovery_challenge::{RecoveryChallengeError, RecoveryChallengeStore};
pub use domain::transfer_nonce::{TransferNonceStore, TransferStateStore};

// Trust transfer DTO (insulates presentation from domain struct layout)
pub use crate::dto::EncryptedTransferStateDto;

// Event types
pub use domain::DeviceEvent;

