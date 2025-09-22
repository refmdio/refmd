use std::env;

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
    pub uploads_dir: String,
    pub plugin_dir: String,
    pub encryption_key: String,
    pub upload_max_bytes: usize,
    pub public_base_url: Option<String>,
    pub is_production: bool,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let api_port = env::var("API_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8888);
        let frontend_url = env::var("FRONTEND_URL").ok();
        let database_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://refmd:refmd@localhost:5432/refmd".into());
        // HS256 secret in PEM or bare string (we'll accept either)
        let jwt_secret_pem =
            env::var("JWT_SECRET").unwrap_or_else(|_| "development-secret-change-me".into());
        let jwt_expires_secs = env::var("JWT_EXPIRES_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60 * 60);
        let snapshot_interval_secs = env::var("SNAPSHOT_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(300);
        let snapshot_keep_versions = env::var("SNAPSHOT_KEEP_VERSIONS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);
        let updates_keep_window = env::var("UPDATES_KEEP_WINDOW")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(500);
        let uploads_dir = env::var("UPLOADS_DIR").unwrap_or_else(|_| "./uploads".into());
        let plugin_dir = env::var("PLUGINS_DIR").unwrap_or_else(|_| "./plugins".into());
        let encryption_key = env::var("ENCRYPTION_KEY").unwrap_or_else(|_| jwt_secret_pem.clone());
        let upload_max_bytes = env::var("UPLOAD_MAX_BYTES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(25 * 1024 * 1024);
        let public_base_url = env::var("PUBLIC_BASE_URL").ok().and_then(|v| {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                None
            } else if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                Some(trimmed.trim_end_matches('/').to_string())
            } else {
                None
            }
        });
        let is_production = matches!(
            env::var("RUST_ENV").ok().as_deref(),
            Some("production") | Some("prod")
        );

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
            uploads_dir,
            plugin_dir,
            encryption_key,
            upload_max_bytes,
            public_base_url,
            is_production,
        })
    }
}
