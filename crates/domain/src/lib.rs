//! Domain layer - Core business logic and entities
//!
//! This layer contains:
//! - Entities: Core business objects with identity
//! - Value Objects: Immutable objects defined by their attributes
//! - Domain Events: Events that occur within the domain
//! - Repository Traits: Interfaces for data access (implemented in infrastructure)
//! - Domain Services: Business logic that doesn't belong to a single entity

#[macro_use]
mod id_macro;

pub mod crypto_validation;
pub mod device_events;
pub mod document;
pub mod encryption;
pub mod identity;
pub mod pop;
pub mod recovery_challenge;
pub mod signature;
pub mod transfer_nonce;
pub mod workspace;

// Re-export commonly used types
pub use device_events::DeviceEvent;
pub use pop::{ChallengeError, ChallengeStore};
pub use recovery_challenge::{RecoveryChallengeError, RecoveryChallengeStore};
pub use signature::{
    SignatureAction, SignatureError, build_pop_signature_message, build_signature_message,
};
pub use transfer_nonce::{
    EncryptedTransferState, TransferNonceError, TransferNonceStore, TransferStateError,
    TransferStateStore,
};
