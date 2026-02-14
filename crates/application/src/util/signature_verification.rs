//! Shared Ed25519 signature verification utility
//!
//! Consolidates the common pattern of parsing public key bytes,
//! signature bytes, and verifying an Ed25519 signature.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use thiserror::Error;

/// Errors that can occur during Ed25519 signature verification
#[derive(Debug, Error)]
pub enum SignatureVerificationError {
    #[error("invalid public key length: expected 32 bytes, got {0}")]
    InvalidPublicKeyLength(usize),

    #[error("invalid public key format")]
    InvalidPublicKeyFormat,

    #[error("invalid signature length: expected 64 bytes, got {0}")]
    InvalidSignatureLength(usize),

    #[error("signature verification failed")]
    VerificationFailed,
}

/// Verify an Ed25519 signature over a message.
///
/// This is the low-level building block used by all signature verification
/// in the application layer. Callers are responsible for constructing the
/// correct `message` bytes (typically via `build_signature_message`).
pub fn verify_ed25519_signature(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), SignatureVerificationError> {
    // Parse public key (32 bytes for Ed25519)
    let pk_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| SignatureVerificationError::InvalidPublicKeyLength(public_key.len()))?;

    let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| SignatureVerificationError::InvalidPublicKeyFormat)?;

    // Parse signature (64 bytes for Ed25519)
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| SignatureVerificationError::InvalidSignatureLength(signature.len()))?;

    let sig = Signature::from_bytes(&sig_bytes);

    // Verify
    verifying_key
        .verify(message, &sig)
        .map_err(|_| SignatureVerificationError::VerificationFailed)
}

/// Maps a [`SignatureVerificationError`] to a caller-specific error type.
///
/// The three mapping closures correspond to the three failure categories:
/// - `on_invalid_key`: public key length or format error
/// - `on_invalid_sig`: signature length error
/// - `on_verification_failed`: cryptographic verification failure
pub fn map_sig_error<E>(
    e: SignatureVerificationError,
    on_invalid_key: impl FnOnce() -> E,
    on_invalid_sig: impl FnOnce() -> E,
    on_verification_failed: impl FnOnce() -> E,
) -> E {
    match e {
        SignatureVerificationError::InvalidPublicKeyLength(_)
        | SignatureVerificationError::InvalidPublicKeyFormat => on_invalid_key(),
        SignatureVerificationError::InvalidSignatureLength(_) => on_invalid_sig(),
        SignatureVerificationError::VerificationFailed => on_verification_failed(),
    }
}
