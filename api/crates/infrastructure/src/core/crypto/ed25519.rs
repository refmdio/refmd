//! Ed25519 signature verification for E2EE messages
//!
//! This module provides signature verification for E2EE realtime messages.
//! The server verifies signatures to ensure message integrity and authenticity,
//! but does not decrypt the message content.
//!
//! Signature format follows secsync specification:
//! `domain + canonicalize({nonce, ciphertext, publicData})`

use anyhow::Result;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Ed25519 signature verifier for E2EE messages
pub struct Ed25519Verifier;

impl Ed25519Verifier {
    /// Verify an Ed25519 signature
    ///
    /// # Arguments
    /// * `public_key` - 32-byte Ed25519 public key
    /// * `message` - Message bytes to verify
    /// * `signature` - 64-byte Ed25519 signature
    ///
    /// # Returns
    /// * `Ok(true)` if signature is valid
    /// * `Ok(false)` if signature is invalid
    /// * `Err` if key/signature format is invalid
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        // Validate key length (32 bytes)
        if public_key.len() != 32 {
            anyhow::bail!(
                "invalid public key length: expected 32, got {}",
                public_key.len()
            );
        }

        // Validate signature length (64 bytes)
        if signature.len() != 64 {
            anyhow::bail!(
                "invalid signature length: expected 64, got {}",
                signature.len()
            );
        }

        let verifying_key = VerifyingKey::from_bytes(
            public_key
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid public key"))?,
        )
        .map_err(|e| anyhow::anyhow!("failed to parse public key: {}", e))?;

        let sig = Signature::from_bytes(
            signature
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid signature"))?,
        );

        Ok(verifying_key.verify(message, &sig).is_ok())
    }

    /// Build message bytes for signature verification (secsync format)
    ///
    /// Format: `domain + canonicalize({nonce, ciphertext, publicData})`
    ///
    /// Where canonicalize produces deterministic JSON (RFC 8785 JSON Canonicalization Scheme).
    /// The publicData is passed as a Base64-encoded string (already canonicalized by client).
    ///
    /// # Arguments
    /// * `domain` - Signature domain (e.g., "refmd_update", "refmd_snapshot", "refmd_ephemeral")
    /// * `nonce` - Base64-encoded nonce string
    /// * `ciphertext` - Base64-encoded ciphertext string
    /// * `public_data` - Base64-encoded canonicalized publicData string
    pub fn build_signing_message(
        domain: &str,
        nonce: &str,
        ciphertext: &str,
        public_data: &str,
    ) -> Vec<u8> {
        // Canonicalize {nonce, ciphertext, publicData} as JSON
        // Keys must be sorted alphabetically per RFC 8785
        let canonical_json = format!(
            r#"{{"ciphertext":"{}","nonce":"{}","publicData":"{}"}}"#,
            ciphertext, nonce, public_data
        );

        // domain + canonicalized JSON
        let mut message = Vec::with_capacity(domain.len() + canonical_json.len());
        message.extend_from_slice(domain.as_bytes());
        message.extend_from_slice(canonical_json.as_bytes());
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_signing_message_secsync_format() {
        let msg = Ed25519Verifier::build_signing_message(
            "refmd_update",
            "bm9uY2U=",      // "nonce" in base64
            "Y2lwaGVy",      // "cipher" in base64
            "cHVibGljRGF0YQ==", // "publicData" in base64
        );

        let expected = r#"refmd_update{"ciphertext":"Y2lwaGVy","nonce":"bm9uY2U=","publicData":"cHVibGljRGF0YQ=="}"#;
        assert_eq!(String::from_utf8(msg).unwrap(), expected);
    }

    #[test]
    fn test_verify_invalid_key_length() {
        let result = Ed25519Verifier::verify(&[0u8; 16], &[0u8; 32], &[0u8; 64]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid public key length"));
    }

    #[test]
    fn test_verify_invalid_signature_length() {
        let result = Ed25519Verifier::verify(&[0u8; 32], &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid signature length"));
    }
}
