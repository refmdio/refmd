use sha2::{Digest, Sha256};

/// Return lowercase hex SHA-256 for arbitrary bytes.
pub fn sha256_hex<T: AsRef<[u8]>>(input: T) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_ref());
    hex::encode(hasher.finalize())
}

/// Convenience helper for string inputs.
pub fn sha256_hex_str(input: &str) -> String {
    sha256_hex(input.as_bytes())
}
