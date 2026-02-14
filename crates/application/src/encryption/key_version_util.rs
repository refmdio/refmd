//! Shared key-version validation utility

use domain::encryption::KeyVersion;

/// Error returned when a user-supplied key version is invalid.
#[derive(Debug)]
pub struct InvalidKeyVersionError;

/// Validate an explicit (user-supplied) key version.
///
/// Ensures the value is positive, fits in `i32`, and produces a valid
/// [`KeyVersion`].
pub fn validate_explicit_key_version(v: u32) -> Result<KeyVersion, InvalidKeyVersionError> {
    if v > i32::MAX as u32 {
        return Err(InvalidKeyVersionError);
    }
    KeyVersion::new(v as i32).map_err(|_| InvalidKeyVersionError)
}

/// Auto-resolve the next key version from existing versions and a minimum version.
///
/// Returns `max(max_existing + 1, min_version)` as a [`KeyVersion`].
/// When `existing_versions` is empty the result is `max(1, min_version)`.
pub fn auto_resolve_key_version(
    existing_versions: impl Iterator<Item = i32>,
    min_version: i32,
) -> KeyVersion {
    let max_existing = existing_versions.max().unwrap_or(0);
    let next = std::cmp::max(max_existing.saturating_add(1), min_version);
    KeyVersion::new(next).expect("computed key version must be >= 1")
}
