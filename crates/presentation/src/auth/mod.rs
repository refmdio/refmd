//! Authentication extractors and middleware
//!
//! Provides authentication helpers for authenticated requests.
//!
//! - `session` — Session-based authentication (AuthUser)
//! - `pop` — Proof-of-Possession verification (PopVerifiedUser, RecoveryOrPopUser)
//! - `pop_layer` — Tower middleware for route-level PoP verification

pub(crate) mod pop;
pub(crate) mod pop_layer;
mod session;

pub use pop::{
    POP_CHALLENGE_HEADER, POP_DEVICE_ID_HEADER, POP_SIGNATURE_HEADER, PopVerifiedUser,
    RecoveryOrPopUser,
};
pub use pop_layer::PopLayer;
pub use session::{
    AuthError, AuthUser, extract_session_token,
    hash_session_token,
};
pub(crate) use session::authenticate;
