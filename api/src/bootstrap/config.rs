use std::env;
use std::str::FromStr;

fn env_var(keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Ok(value) = env::var(key) {
            if !value.trim().is_empty() {
                return Some(value);
            }
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
    pub snapshot_interval_secs: u64,
    pub snapshot_keep_versions: i64,
    pub updates_keep_window: i64,
    pub storage_backend: StorageBackend,
    pub storage_root: String,
    pub s3_endpoint: Option<String>,
    pub s3_bucket: Option<String>,
    pub s3_region: Option<String>,
    pub s3_access_key: Option<String>,
    pub s3_secret_key: Option<String>,
    pub s3_use_path_style: bool,
    pub plugin_dir: String,
    pub encryption_key: String,
    pub upload_max_bytes: usize,
    pub public_base_url: Option<String>,
    pub is_production: bool,
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
        let s3_endpoint = env_var(&["S3_ENDPOINT"]);
        let s3_bucket = env_var(&["S3_BUCKET"]);
        let s3_region = env_var(&["S3_REGION"]);
        let s3_access_key = env_var(&["S3_ACCESS_KEY"]);
        let s3_secret_key = env_var(&["S3_SECRET_KEY"]);
        let s3_use_path_style = env_var(&["S3_USE_PATH_STYLE"])
            .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true"))
            .unwrap_or(false);
        let plugin_dir = env_var(&["PLUGINS_DIR"]).unwrap_or_else(|| "./plugins".into());
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

        // Production hardening: require proper FRONTEND_URL and robust secrets
        if is_production {
            if frontend_url
                .as_deref()
                .map(|u| u.starts_with("http"))
                .unwrap_or(false)
                == false
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

        Ok(Self {
            api_port,
            frontend_url,
            database_url,
            jwt_secret_pem,
            jwt_expires_secs,
            snapshot_interval_secs,
            snapshot_keep_versions,
            updates_keep_window,
            storage_backend,
            storage_root,
            s3_endpoint,
            s3_bucket,
            s3_region,
            s3_access_key,
            s3_secret_key,
            s3_use_path_style,
            plugin_dir,
            encryption_key,
            upload_max_bytes,
            public_base_url,
            is_production,
        })
    }
}
