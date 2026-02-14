//! Sub-states for gradual handler migration
//!
//! Route handlers can extract `State<WorkspaceSubState>` (etc.) instead of
//! `State<AppState>` to limit the set of repositories they depend on.
//! Existing `State<AppState>` extractions continue to work unchanged.

use super::type_aliases::*;
use super::AppState;

/// Macro to implement `FromRef<AppState>` for sub-states.
///
/// Each field is cloned from `AppState` via `Arc::clone` (for Arc fields)
/// or plain clone/copy (for non-Arc fields like `bool`).
macro_rules! impl_from_ref {
    ($sub:ident { $( $field:ident $( @ $clone_fn:expr )? ),+ $(,)? }) => {
        impl axum::extract::FromRef<AppState> for $sub {
            fn from_ref(state: &AppState) -> Self {
                Self {
                    $( $field: impl_from_ref!(@clone state.$field $( , $clone_fn )? ), )+
                }
            }
        }
    };
    // Default: Arc::clone
    (@clone $expr:expr) => { Arc::clone(&$expr) };
    // Custom clone function
    (@clone $expr:expr, $clone_fn:expr) => { ($clone_fn)(&$expr) };
}

mod auth;
mod device;
mod document;
mod encryption;
mod trust_transfer;
mod workspace;

pub use auth::AuthSubState;
pub use device::DeviceSubState;
pub use document::DocumentSubState;
pub use encryption::EncryptionSubState;
pub use trust_transfer::TrustTransferSubState;
pub use workspace::WorkspaceSubState;
