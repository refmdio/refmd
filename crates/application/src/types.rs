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

/// Captured classification flags from a typed error before erasure.
///
/// When a concrete repository error (e.g., `PgWorkspaceRoleRepositoryError`)
/// is wrapped into `BoxedError`, the classifier trait methods are evaluated
/// eagerly and their results stored here. This avoids brittle string-based
/// classification after type erasure.
#[derive(Debug, Default, Clone, Copy)]
pub struct ErrorClassification {
    pub role_in_use: bool,
    pub role_became_default: bool,
    pub role_not_found: bool,
    pub slug_conflict: bool,
}

/// A concrete error type that wraps a boxed error for object safety.
/// This is needed because `Box<dyn Error>` doesn't implement `Error` (Sized requirement).
///
/// Classification flags are captured at construction time (before type erasure)
/// so downstream code can classify without string matching.
pub struct BoxedError {
    inner: Box<dyn std::error::Error + Send + Sync>,
    /// Stored separately for type-safe downcasting (dyn Error can't be cast to dyn Any).
    any: Box<dyn std::any::Any + Send + Sync>,
    classification: ErrorClassification,
}

impl BoxedError {
    /// Wrap an error, capturing no classification flags.
    pub fn new(e: impl std::error::Error + Send + Sync + 'static) -> Self {
        // Clone the error into both trait-object channels: Error for display, Any for downcast
        let display_msg = e.to_string();
        Self {
            any: Box::new(e),
            inner: Box::new(StringError(display_msg)),
            classification: ErrorClassification::default(),
        }
    }

    /// Wrap a role-repository error, capturing its classifier flags eagerly.
    pub fn from_role_repo(e: impl std::error::Error + domain::workspace::WorkspaceRoleRepositoryErrorClassifier + Send + Sync + 'static) -> Self {
        let classification = ErrorClassification {
            role_in_use: e.is_role_in_use(),
            role_became_default: e.is_role_became_default(),
            role_not_found: e.is_role_not_found(),
            ..Default::default()
        };
        let display_msg = e.to_string();
        Self {
            any: Box::new(e),
            inner: Box::new(StringError(display_msg)),
            classification,
        }
    }

    /// Wrap a workspace-repository error, capturing its classifier flags eagerly.
    pub fn from_workspace_repo(e: impl std::error::Error + domain::workspace::WorkspaceRepositoryErrorClassifier + Send + Sync + 'static) -> Self {
        let classification = ErrorClassification {
            slug_conflict: e.is_slug_conflict(),
            ..Default::default()
        };
        let display_msg = e.to_string();
        Self {
            any: Box::new(e),
            inner: Box::new(StringError(display_msg)),
            classification,
        }
    }

    /// Downcast the inner error to a concrete type.
    pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        self.any.downcast_ref::<T>()
    }
}

/// Internal error type that holds a captured error message.
/// Used because `BoxedError` stores the concrete error in `any: Box<dyn Any>`
/// (for downcasting) rather than `inner: Box<dyn Error>` (for display).
#[derive(Debug)]
struct StringError(String);

impl std::fmt::Display for StringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StringError {}

impl std::fmt::Debug for BoxedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxedError")
            .field("message", &self.inner.to_string())
            .field("classification", &self.classification)
            .finish()
    }
}

impl std::fmt::Display for BoxedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl std::error::Error for BoxedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

// Classifier implementations for BoxedError.
// Classification flags were captured at construction time, so these
// are simple field lookups with no string parsing.
impl domain::workspace::WorkspaceRoleRepositoryErrorClassifier for BoxedError {
    fn is_role_in_use(&self) -> bool {
        self.classification.role_in_use
    }
    fn is_role_became_default(&self) -> bool {
        self.classification.role_became_default
    }
    fn is_role_not_found(&self) -> bool {
        self.classification.role_not_found
    }
}
impl domain::workspace::WorkspaceRepositoryErrorClassifier for BoxedError {
    fn is_slug_conflict(&self) -> bool {
        self.classification.slug_conflict
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
/// | `unprocessable`     | Semantically invalid operation          | 422                 |
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
    fn is_unprocessable(&self) -> bool {
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
        $(unprocessable: [$($up:pat),+ $(,)?] $(,)?)?
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
            $(
                fn is_unprocessable(&self) -> bool {
                    matches!(self, $($up)|+)
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
        $(unprocessable: [$($up:pat),+ $(,)?] $(,)?)?
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
            $(
                fn is_unprocessable(&self) -> bool {
                    matches!(self, $($up)|+)
                }
            )?
        }
    };
}

pub(crate) use impl_app_error;

// Domain crypto validation (re-exported for presentation layer)
pub use domain::crypto_validation;

// ID types
pub use domain::document::{DocumentId, DocumentSnapshotId};
pub use domain::encryption::{DeviceId, DeviceType, RevocationMode};
pub use domain::identity::{SessionId, UserId};
pub use domain::workspace::{BaseRole, InvitationId, RoleId, WorkspaceId};

// Repository traits
pub use domain::document::{DocumentRepository, DocumentSnapshotRepository, DocumentUpdateRepository, SnapshotSaveOutcome};
pub use domain::encryption::{
    DeviceEncryptedUMKRepository, DeviceRepository, DeviceRevocationEventRepository,
    DocumentEncryptedKeyRepository, PendingDeviceRepository, UserEncryptedIdentityKeyRepository,
    UserEncryptedMasterKeyRepository, UserIdentityPublicKeyRepository,
    WorkspaceEncryptedKeyRepository, WorkspaceKekBackupRepository,
};
pub use domain::identity::{SessionRepository, UserRepository, UserSettingsRepository};
pub use domain::workspace::{
    WorkspaceInvitationRepository, WorkspaceMemberRepository, WorkspaceRepository,
    WorkspaceRolePermissionRepository, WorkspaceRoleRepository,
};

// Entity types
pub use domain::document::{Document, DocumentSnapshot, DocumentUpdate, SnapshotProof};
pub use domain::encryption::{
    Device, DeviceEncryptedUMK, DeviceRevocationEvent, DocumentEncryptedKey, PendingDevice,
    UserEncryptedIdentityKey, UserEncryptedMasterKey, UserIdentityPublicKey,
    WorkspaceEncryptedKey, WorkspaceKekBackup,
};
pub use domain::identity::{Email, Session, User, UserSettings};
pub use domain::workspace::{
    Slug, Workspace, WorkspaceInvitation, WorkspaceMember, WorkspaceRole, WorkspaceRolePermission,
};

// Store traits
pub use domain::pop::{ChallengeError, ChallengeStore};
pub use domain::recovery_challenge::{RecoveryChallengeError, RecoveryChallengeStore};
pub use domain::transfer_nonce::{TransferNonceStore, TransferStateStore};

// Trust transfer DTO (insulates presentation from domain struct layout)
pub use crate::dto::EncryptedTransferStateDto;

// Event types
pub use domain::DeviceEvent;
pub use domain::WorkspaceEvent;

