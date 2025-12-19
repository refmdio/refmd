use std::env;
use std::str::FromStr;

fn env_var(keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Ok(value) = env::var(key) && !value.trim().is_empty() {
            return Some(value);
        }
    }
    None
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StorageBackend {
    Filesystem,
    S3,
}

impl FromStr for StorageBackend {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "filesystem" | "fs" => Ok(StorageBackend::Filesystem),
            "s3" => Ok(StorageBackend::S3),
            other => Err(anyhow::anyhow!("unsupported storage backend: {}", other)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub api_port: u16,
    pub frontend_url: Option<String>,
    pub database_url: String,
    pub jwt_secret_pem: String,
    pub jwt_expires_secs: i64,
    pub session_refresh_ttl_secs: i64,
    pub session_refresh_remember_ttl_secs: i64,
    pub snapshot_interval_secs: u64,
    pub snapshot_keep_versions: i64,
    pub updates_keep_window: i64,
    pub storage_backend: StorageBackend,
    pub storage_root: String,
    pub storage_monitor_enabled: bool,
    pub storage_monitor_interval_secs: u64,
    pub storage_monitor_batch_size: i64,
    pub s3_endpoint: Option<String>,
    pub s3_bucket: Option<String>,
    pub s3_region: Option<String>,
    pub s3_access_key: Option<String>,
    pub s3_secret_key: Option<String>,
    pub s3_use_path_style: bool,
    pub plugin_dir: String,
    pub plugin_timeout_secs: u64,
    pub plugin_memory_max_mb: u64,
    pub plugin_fuel_limit: Option<u64>,
    pub plugin_asset_sign_key: String,
    pub plugin_asset_url_ttl_secs: u64,
    pub encryption_key: String,
    pub upload_max_bytes: usize,
    pub public_base_url: Option<String>,
    pub is_production: bool,
    pub cluster_mode: bool,
    pub redis_url: Option<String>,
    pub redis_stream_prefix: String,
    pub redis_min_message_lifetime_ms: u64,
    pub redis_task_debounce_ms: u64,
    pub redis_awareness_ttl_ms: u64,
    pub redis_stream_max_len: usize,
    pub snapshot_archive_interval_secs: u64,
    pub git_rebuild_enabled: bool,
    pub git_rebuild_interval_secs: u64,
    pub google_oauth: Option<GoogleOAuthConfig>,
    pub github_oauth: Option<GithubOAuthConfig>,
    pub oidc_oauth: Option<OidcOAuthConfig>,
}

#[derive(Clone, Debug)]
pub struct GoogleOAuthConfig {
    pub client_ids: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct GithubOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug)]
pub struct OidcOAuthConfig {
    pub issuer_url: String,
    pub discovery_url: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: Option<String>,
    pub scopes: Vec<String>,
    pub display_name: Option<String>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let api_port = env_var(&["API_PORT", "PORT"])
            .and_then(|s| s.parse().ok())
            .unwrap_or(8888);
        let frontend_url = env_var(&["FRONTEND_URL", "FRONTEND_ORIGIN"]);
        let database_url = env_var(&["DATABASE_URL"])
            .unwrap_or_else(|| "postgres://refmd:refmd@localhost:5432/refmd".into());
        // HS256 secret in PEM or bare string (we'll accept either)
        let jwt_secret_pem =
            env_var(&["JWT_SECRET"]).unwrap_or_else(|| "development-secret-change-me".into());
        let jwt_expires_secs = env_var(&["JWT_EXPIRES_SECS"])
            .and_then(|s| s.parse().ok())
            .unwrap_or(60 * 60);
        let session_refresh_ttl_secs = env_var(&["SESSION_REFRESH_TTL_SECS"])
            .and_then(|s| s.parse().ok())
            .unwrap_or(60 * 60 * 24);
        let session_refresh_remember_ttl_secs = env_var(&["SESSION_REFRESH_REMEMBER_TTL_SECS"])
            .and_then(|s| s.parse().ok())
            .unwrap_or(60 * 60 * 24 * 30);
        let snapshot_interval_secs = env_var(&["SNAPSHOT_INTERVAL_SECS"])
            .and_then(|s| s.parse().ok())
            .unwrap_or(300);
        let snapshot_keep_versions = env_var(&["SNAPSHOT_KEEP_VERSIONS"])
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);
        let updates_keep_window = env_var(&["UPDATES_KEEP_WINDOW"])
            .and_then(|s| s.parse().ok())
            .unwrap_or(500);
        let storage_backend = env_var(&["STORAGE_BACKEND"])
            .as_deref()
            .unwrap_or("filesystem")
            .parse::<StorageBackend>()?;
        let storage_root =
            env_var(&["STORAGE_ROOT", "UPLOADS_DIR"]).unwrap_or_else(|| "./uploads".into());
        let storage_monitor_enabled = env_var(&["STORAGE_MONITOR_ENABLED"])
            .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(true);
        let storage_monitor_interval_secs = env_var(&["STORAGE_MONITOR_INTERVAL_SECS"])
            .and_then(|s| s.parse().ok())
            .unwrap_or(600);
        let storage_monitor_batch_size = env_var(&["STORAGE_MONITOR_BATCH_SIZE"])
            .and_then(|s| s.parse().ok())
            .unwrap_or(200);
        let s3_endpoint = env_var(&["S3_ENDPOINT"]);
        let s3_bucket = env_var(&["S3_BUCKET"]);
        let s3_region = env_var(&["S3_REGION"]);
        let s3_access_key = env_var(&["S3_ACCESS_KEY"]);
        let s3_secret_key = env_var(&["S3_SECRET_KEY"]);
        let s3_use_path_style = env_var(&["S3_USE_PATH_STYLE"])
            .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true"))
            .unwrap_or(false);
        let plugin_dir = env_var(&["PLUGINS_DIR"]).unwrap_or_else(|| "./plugins".into());
        let plugin_timeout_secs = env_var(&["PLUGIN_TIMEOUT_SECS"])
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);
        let plugin_memory_max_mb = env_var(&["PLUGIN_MEMORY_MAX_MB"])
            .and_then(|s| s.parse().ok())
            .unwrap_or(256);
        let plugin_fuel_limit = env_var(&["PLUGIN_FUEL_LIMIT"]).and_then(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                trimmed.parse().ok()
            }
        });
        let plugin_asset_sign_key = env_var(&["PLUGIN_ASSET_SIGN_KEY"])
            .unwrap_or_else(|| "development-plugin-sign-key".into());
        let plugin_asset_url_ttl_secs = env_var(&["PLUGIN_ASSET_URL_TTL_SECS"])
            .and_then(|s| s.parse().ok())
            .unwrap_or(120);
        let encryption_key = env_var(&["ENCRYPTION_KEY"]).unwrap_or_else(|| jwt_secret_pem.clone());
        let upload_max_bytes = env_var(&["UPLOAD_MAX_BYTES"])
            .and_then(|s| s.parse().ok())
            .unwrap_or(25 * 1024 * 1024);
        let public_base_url =
            env_var(&["BACKEND_URL", "API_URL", "PUBLIC_BASE_URL", "PUBLIC_ORIGIN"])
                .and_then(|v| {
                    let trimmed = v.trim();
                    if trimmed.is_empty() {
                        None
                    } else if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                        Some(trimmed.trim_end_matches('/').to_string())
                    } else {
                        None
                    }
                })
                .or_else(|| frontend_url.clone());
        let runtime_env = env_var(&["RUST_ENV", "APP_ENV"]).unwrap_or_else(|| "production".into());
        let is_production = matches!(runtime_env.as_str(), "production" | "prod" | "release");

        let cluster_mode = env_var(&["CLUSTER_MODE"])
            .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        let redis_url = env_var(&["REDIS_URL"]);
        let redis_stream_prefix = env_var(&["REDIS_STREAM_PREFIX"]).unwrap_or_else(|| "yrs".into());
        let redis_min_message_lifetime_ms = env_var(&["REDIS_MIN_MESSAGE_LIFETIME_MS"])
            .and_then(|s| s.parse().ok())
            .unwrap_or(60_000);
        let redis_task_debounce_ms = env_var(&["REDIS_TASK_DEBOUNCE_MS"])
            .and_then(|s| s.parse().ok())
            .unwrap_or(10_000);
        let redis_awareness_ttl_ms = env_var(&["REDIS_AWARENESS_TTL_MS"])
            .and_then(|s| s.parse().ok())
            .unwrap_or(45_000);
        let redis_stream_max_len = env_var(&["REDIS_STREAM_MAX_LEN"])
            .and_then(|s| s.parse().ok())
            .unwrap_or(4096);
        let snapshot_archive_interval_secs = env_var(&["SNAPSHOT_ARCHIVE_INTERVAL_SECS"])
            .and_then(|s| s.parse().ok())
            .unwrap_or(900);
        let git_rebuild_enabled = env_var(&["GIT_REBUILD_ENABLED"])
            .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(true);
        let git_rebuild_interval_secs = env_var(&["GIT_REBUILD_INTERVAL_SECS"])
            .and_then(|s| s.parse().ok())
            .unwrap_or(6 * 60 * 60);
        let google_oauth = env_var(&["GOOGLE_OAUTH_CLIENT_IDS", "GOOGLE_OAUTH_CLIENT_ID"])
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            })
            .filter(|ids| !ids.is_empty())
            .map(|ids| GoogleOAuthConfig { client_ids: ids });
        let github_oauth = match (
            env_var(&["GITHUB_OAUTH_CLIENT_ID"]),
            env_var(&["GITHUB_OAUTH_CLIENT_SECRET"]),
        ) {
            (Some(client_id), Some(client_secret))
                if !client_id.is_empty() && !client_secret.is_empty() =>
            {
                Some(GithubOAuthConfig {
                    client_id,
                    client_secret,
                    redirect_uri: env_var(&["GITHUB_OAUTH_REDIRECT_URI"]),
                })
            }
            _ => None,
        };
        let oidc_oauth = match (
            env_var(&["OIDC_OAUTH_ISSUER", "OIDC_OAUTH_ISSUER_URL"]),
            env_var(&["OIDC_OAUTH_CLIENT_ID"]),
            env_var(&["OIDC_OAUTH_CLIENT_SECRET"]),
        ) {
            (Some(issuer_url), Some(client_id), Some(client_secret))
                if !issuer_url.trim().is_empty()
                    && !client_id.trim().is_empty()
                    && !client_secret.trim().is_empty() =>
            {
                let scopes = env_var(&["OIDC_OAUTH_SCOPES"]).map(|raw| {
                    raw.split(',')
                        .flat_map(|part| part.split_whitespace())
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty())
                        .collect::<Vec<_>>()
                });
                Some(OidcOAuthConfig {
                    issuer_url,
                    discovery_url: env_var(&["OIDC_OAUTH_DISCOVERY_URL"]),
                    client_id,
                    client_secret,
                    redirect_uri: env_var(&["OIDC_OAUTH_REDIRECT_URI"]),
                    scopes: scopes.unwrap_or_default(),
                    display_name: env_var(&["OIDC_OAUTH_DISPLAY_NAME"]),
                })
            }
            _ => None,
        };

        // Production hardening: require proper FRONTEND_URL and robust secrets
        if is_production {
            if !frontend_url
                .as_deref()
                .is_some_and(|u| u.starts_with("http"))
            {
                anyhow::bail!(
                    "FRONTEND_URL must be set to a full origin in production (e.g., https://app.example.com)"
                );
            }
            if jwt_secret_pem == "development-secret-change-me" || jwt_secret_pem.len() < 16 {
                anyhow::bail!("JWT_SECRET must be set to a strong secret in production");
            }
            if encryption_key == "development-secret-change-me" || encryption_key.len() < 16 {
                anyhow::bail!("ENCRYPTION_KEY must be set to a strong secret in production");
            }
            if plugin_asset_sign_key == "development-plugin-sign-key"
                || plugin_asset_sign_key.len() < 16
            {
                anyhow::bail!("PLUGIN_ASSET_SIGN_KEY must be set to a strong secret in production");
            }
            if matches!(storage_backend, StorageBackend::S3) {
                if s3_bucket.as_deref().unwrap_or("").is_empty() {
                    anyhow::bail!(
                        "S3_BUCKET must be configured in production when storage backend is S3"
                    );
                }
                if s3_access_key.as_deref().unwrap_or("").is_empty()
                    || s3_secret_key.as_deref().unwrap_or("").is_empty()
                {
                    anyhow::bail!(
                        "S3_ACCESS_KEY and S3_SECRET_KEY must be configured in production when storage backend is S3"
                    );
                }
            }
        }

        if cluster_mode && redis_url.is_none() {
            anyhow::bail!("REDIS_URL must be configured when CLUSTER_MODE is enabled");
        }

        Ok(Self {
            api_port,
            frontend_url,
            database_url,
            jwt_secret_pem,
            jwt_expires_secs,
            session_refresh_ttl_secs,
            session_refresh_remember_ttl_secs,
            snapshot_interval_secs,
            snapshot_keep_versions,
            updates_keep_window,
            storage_backend,
            storage_root,
            storage_monitor_enabled,
            storage_monitor_interval_secs,
            storage_monitor_batch_size,
            s3_endpoint,
            s3_bucket,
            s3_region,
            s3_access_key,
            s3_secret_key,
            s3_use_path_style,
            plugin_dir,
            plugin_timeout_secs,
            plugin_memory_max_mb,
            plugin_fuel_limit,
            plugin_asset_sign_key,
            plugin_asset_url_ttl_secs,
            encryption_key,
            upload_max_bytes,
            public_base_url,
            is_production,
            cluster_mode,
            redis_url,
            redis_stream_prefix,
            redis_min_message_lifetime_ms,
            redis_task_debounce_ms,
            redis_awareness_ttl_ms,
            redis_stream_max_len,
            snapshot_archive_interval_secs,
            git_rebuild_enabled,
            git_rebuild_interval_secs,
            google_oauth,
            github_oauth,
            oidc_oauth,
        })
    }
}
