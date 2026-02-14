//! Authentication extractors and middleware
//!
//! Provides authentication helpers for authenticated requests.
//!
//! - `session` — Session-based authentication (AuthUser)
//! - `pop` — Proof-of-Possession verification (PopVerifiedUser, RecoveryOrPopUser)

pub(crate) mod pop;
mod session;

pub use pop::{
    POP_CHALLENGE_HEADER, POP_DEVICE_ID_HEADER, POP_SIGNATURE_HEADER, PopVerifiedUser,
    RecoveryOrPopUser,
};
pub use session::{
    AuthError, AuthUser, authenticate, extract_session_token,
    hash_session_token,
};
