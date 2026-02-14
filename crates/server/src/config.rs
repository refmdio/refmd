//! Server configuration helpers
//!
//! Reads configuration from environment variables.

/// Load server secret from environment variable.
/// SERVER_SECRET must be a 64-character hex string (32 bytes).
pub(crate) fn load_server_secret() -> anyhow::Result<[u8; 32]> {
    let secret_hex = std::env::var("SERVER_SECRET")
        .map_err(|_| anyhow::anyhow!("SERVER_SECRET environment variable is required"))?;

    if secret_hex.len() != 64 {
        return Err(anyhow::anyhow!(
            "SERVER_SECRET must be exactly 64 hex characters (32 bytes)"
        ));
    }

    let mut secret = [0u8; 32];
    hex::decode_to_slice(&secret_hex, &mut secret)
        .map_err(|e| anyhow::anyhow!("Invalid SERVER_SECRET hex encoding: {}", e))?;

    Ok(secret)
}

/// Parse a boolean environment variable ("true"/"1" = true, absent = default).
fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(default)
}

/// Check if cluster mode is enabled via environment variable.
pub(crate) fn is_cluster_enabled() -> bool {
    env_bool("CLUSTER_ENABLED", false)
}

/// Check if Swagger UI is enabled via environment variable.
/// Defaults to false (disabled) for security in production.
pub(crate) fn is_swagger_enabled() -> bool {
    env_bool("ENABLE_SWAGGER", false)
}
