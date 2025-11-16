use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Credentials, Region};
use tokio::task;
use uuid::Uuid;
use walkdir::WalkDir;

use crate::application::ports::storage_reconcile_backend::StorageReconcileBackend;

use super::s3::S3StorageConfig;

pub struct FsReconcileBackend {
    root: PathBuf,
}

impl FsReconcileBackend {
    pub fn new(root: PathBuf) -> Arc<Self> {
        Arc::new(Self { root })
    }
}

#[async_trait]
impl StorageReconcileBackend for FsReconcileBackend {
    async fn list_paths(&self, user_id: Uuid) -> anyhow::Result<Vec<String>> {
        let root = self.root.clone();
        task::spawn_blocking(move || {
            let user_root = root.join(user_id.to_string());
            if !user_root.exists() {
                return Ok(Vec::new());
            }
            let mut paths = Vec::new();
            for entry in WalkDir::new(&user_root).into_iter().filter_map(Result::ok) {
                if entry.path().is_file() {
                    if let Some(rel) = entry
                        .path()
                        .strip_prefix(&root)
                        .ok()
                        .and_then(|p| p.to_str())
                    {
                        paths.push(rel.replace('\\', "/"));
                    }
                }
            }
            Ok(paths)
        })
        .await
        .map_err(|err| anyhow!(err))?
    }
}

pub struct S3ReconcileBackend {
    client: Client,
    bucket: String,
    root_prefix: String,
}

impl S3ReconcileBackend {
    pub async fn new(cfg: &S3StorageConfig) -> anyhow::Result<Arc<Self>> {
        let mut loader = aws_config::defaults(BehaviorVersion::latest());
        if let Some(region) = &cfg.region {
            loader = loader.region(Region::new(region.clone()));
        }
        let shared = loader.load().await;
        let mut builder = aws_sdk_s3::config::Builder::from(&shared);
        if let (Some(access), Some(secret)) = (&cfg.access_key, &cfg.secret_key) {
            builder = builder.credentials_provider(Credentials::new(
                access.clone(),
                secret.clone(),
                None,
                None,
                "refmd-s3-static",
            ));
        }
        if let Some(endpoint) = &cfg.endpoint {
            builder = builder.endpoint_url(endpoint.clone());
        }
        if cfg.use_path_style {
            builder = builder.force_path_style(true);
        }
        let client = Client::from_conf(builder.build());
        Ok(Arc::new(Self {
            client,
            bucket: cfg.bucket.clone(),
            root_prefix: normalize_prefix(&cfg.uploads_root),
        }))
    }

    fn repo_path_from_key(&self, key: &str) -> Option<String> {
        let trimmed = if self.root_prefix.is_empty() {
            key
        } else {
            key.strip_prefix(&format!("{}/", self.root_prefix))
                .unwrap_or(key)
        };
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }
}

#[async_trait]
impl StorageReconcileBackend for S3ReconcileBackend {
    async fn list_paths(&self, user_id: Uuid) -> anyhow::Result<Vec<String>> {
        let mut paths = Vec::new();
        let prefix = if self.root_prefix.is_empty() {
            user_id.to_string()
        } else {
            format!("{}/{}", self.root_prefix, user_id)
        };
        let mut token = None;
        loop {
            let resp = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&prefix)
                .set_continuation_token(token.clone())
                .send()
                .await?;
            for obj in resp.contents() {
                if let Some(key) = obj.key() {
                    if let Some(repo_path) = self.repo_path_from_key(key) {
                        paths.push(repo_path);
                    }
                }
            }
            if let Some(next) = resp.next_continuation_token() {
                token = Some(next.to_string());
            } else {
                break;
            }
        }
        Ok(paths)
    }
}

fn normalize_prefix(root: &Path) -> String {
    let mut parts: Vec<String> = Vec::new();
    for comp in root.components() {
        if let Component::Normal(os) = comp {
            let s = os.to_string_lossy();
            if !s.is_empty() && s != "." {
                parts.push(s.replace('\\', "/"));
            }
        }
    }
    parts.join("/")
}
