//! Session token generation and hashing utilities
//!
//! Shared by login and recovery session flows.

use sha2::{Digest, Sha256};
use std::fmt::Write;

/// Encode a byte slice as a lowercase hex string.
fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut hex, "{:02x}", b).expect("Failed to write hex");
    }
    hex
}

/// Generate a cryptographically secure session token (64-char hex string)
pub fn generate_session_token() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(bytes_to_hex(&bytes))
}

/// Hash session token (SHA-256) for storage/lookup
pub fn hash_session_token(token: &str) -> String {
    let hash = Sha256::digest(token.as_bytes());
    bytes_to_hex(&hash)
}
