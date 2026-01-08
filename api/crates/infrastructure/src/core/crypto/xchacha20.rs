//! XChaCha20-Poly1305 encryption module for E2EE.
//!
//! This module provides AEAD encryption using XChaCha20-Poly1305,
//! which is the recommended cipher for E2EE document encryption.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use zeroize::Zeroize;

/// XChaCha20-Poly1305 nonce size (24 bytes).
pub const NONCE_SIZE: usize = 24;

/// XChaCha20-Poly1305 key size (32 bytes).
pub const KEY_SIZE: usize = 32;

/// Error type for encryption/decryption operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid key length: expected {KEY_SIZE}, got {0}")]
    InvalidKeyLength(usize),

    #[error("Invalid nonce length: expected {NONCE_SIZE}, got {0}")]
    InvalidNonceLength(usize),

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed: authentication tag mismatch or corrupted data")]
    DecryptionFailed,
}

/// Generate a random 24-byte nonce for XChaCha20-Poly1305.
///
/// Each encryption operation MUST use a unique nonce.
/// Using the same nonce twice with the same key is catastrophic.
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Encrypt plaintext using XChaCha20-Poly1305.
///
/// # Arguments
/// * `key` - 32-byte encryption key (DEK)
/// * `plaintext` - Data to encrypt
///
/// # Returns
/// A tuple of (ciphertext, nonce) on success.
/// The ciphertext includes the 16-byte Poly1305 authentication tag.
pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_SIZE]), CryptoError> {
    if key.len() != KEY_SIZE {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKeyLength(key.len()))?;

    let nonce = generate_nonce();
    let xnonce = XNonce::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(xnonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok((ciphertext, nonce))
}

/// Decrypt ciphertext using XChaCha20-Poly1305.
///
/// # Arguments
/// * `key` - 32-byte encryption key (DEK)
/// * `ciphertext` - Encrypted data (including auth tag)
/// * `nonce` - 24-byte nonce used during encryption
///
/// # Returns
/// The decrypted plaintext on success.
pub fn decrypt(
    key: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != KEY_SIZE {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }
    if nonce.len() != NONCE_SIZE {
        return Err(CryptoError::InvalidNonceLength(nonce.len()));
    }

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKeyLength(key.len()))?;

    let xnonce = XNonce::from_slice(nonce);

    cipher
        .decrypt(xnonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Encrypt a DEK with a KEK.
///
/// Used for storing document encryption keys encrypted with workspace keys.
///
/// # Arguments
/// * `kek` - 32-byte Key Encryption Key
/// * `dek` - 32-byte Data Encryption Key to encrypt
///
/// # Returns
/// A tuple of (encrypted_dek, nonce) on success.
pub fn encrypt_dek(kek: &[u8], dek: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_SIZE]), CryptoError> {
    if dek.len() != KEY_SIZE {
        return Err(CryptoError::InvalidKeyLength(dek.len()));
    }
    encrypt(kek, dek)
}

/// Decrypt a DEK with a KEK.
///
/// # Arguments
/// * `kek` - 32-byte Key Encryption Key
/// * `encrypted_dek` - Encrypted DEK (including auth tag)
/// * `nonce` - 24-byte nonce used during encryption
///
/// # Returns
/// The decrypted 32-byte DEK on success.
pub fn decrypt_dek(
    kek: &[u8],
    encrypted_dek: &[u8],
    nonce: &[u8],
) -> Result<[u8; KEY_SIZE], CryptoError> {
    let decrypted = decrypt(kek, encrypted_dek, nonce)?;
    if decrypted.len() != KEY_SIZE {
        return Err(CryptoError::InvalidKeyLength(decrypted.len()));
    }

    let mut dek = [0u8; KEY_SIZE];
    dek.copy_from_slice(&decrypted);
    Ok(dek)
}

/// A wrapper for sensitive key material that zeroizes on drop.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretKey {
    key: [u8; KEY_SIZE],
}

impl SecretKey {
    /// Create a new SecretKey from bytes.
    pub fn new(key: [u8; KEY_SIZE]) -> Self {
        Self { key }
    }

    /// Create from a slice, returning error if length is invalid.
    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength(slice.len()));
        }
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(slice);
        Ok(Self { key })
    }

    /// Get the key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; KEY_SIZE];
        let plaintext = b"Hello, E2EE World!";

        let (ciphertext, nonce) = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext, &nonce).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let key = [0x42u8; KEY_SIZE];
        let plaintext = b"";

        let (ciphertext, nonce) = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext, &nonce).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        let key = [0x42u8; KEY_SIZE];
        let plaintext = vec![0xABu8; 1024 * 1024]; // 1MB

        let (ciphertext, nonce) = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext, &nonce).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_nonce_uniqueness() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = [0x42u8; 16];
        let plaintext = b"test";

        let result = encrypt(&short_key, plaintext);
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength(16))));
    }

    #[test]
    fn test_invalid_nonce_length() {
        let key = [0x42u8; KEY_SIZE];
        let ciphertext = vec![0u8; 32];
        let short_nonce = [0u8; 12];

        let result = decrypt(&key, &ciphertext, &short_nonce);
        assert!(matches!(result, Err(CryptoError::InvalidNonceLength(12))));
    }

    #[test]
    fn test_corrupted_ciphertext() {
        let key = [0x42u8; KEY_SIZE];
        let plaintext = b"Hello, E2EE World!";

        let (mut ciphertext, nonce) = encrypt(&key, plaintext).unwrap();
        // Corrupt the ciphertext
        ciphertext[0] ^= 0xFF;

        let result = decrypt(&key, &ciphertext, &nonce);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_wrong_key() {
        let key1 = [0x42u8; KEY_SIZE];
        let key2 = [0x43u8; KEY_SIZE];
        let plaintext = b"Secret message";

        let (ciphertext, nonce) = encrypt(&key1, plaintext).unwrap();
        let result = decrypt(&key2, &ciphertext, &nonce);

        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_dek_encrypt_decrypt() {
        let kek = [0x42u8; KEY_SIZE];
        let dek = [0x55u8; KEY_SIZE];

        let (encrypted_dek, nonce) = encrypt_dek(&kek, &dek).unwrap();
        let decrypted_dek = decrypt_dek(&kek, &encrypted_dek, &nonce).unwrap();

        assert_eq!(dek, decrypted_dek);
    }

    #[test]
    fn test_secret_key_zeroize() {
        let key_bytes = [0x42u8; KEY_SIZE];
        let secret_key = SecretKey::new(key_bytes);
        assert_eq!(secret_key.as_bytes(), &key_bytes);
        // SecretKey will zeroize on drop
    }
}
