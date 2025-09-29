use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use futures_util::stream;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::application::ports::git_storage::{
    BlobKey, CommitMeta, GitStorage, PackBlob, PackStream, encode_commit_id,
};
use crate::bootstrap::config::{Config, StorageBackend};

pub async fn build_git_storage(cfg: &Config) -> anyhow::Result<Arc<dyn GitStorage>> {
    match cfg.storage_backend {
        StorageBackend::Filesystem => Ok(Arc::new(FilesystemGitStorage::new(
            cfg.storage_root.clone(),
        )) as Arc<dyn GitStorage>),
        StorageBackend::S3 => {
            let storage = S3GitStorage::new(cfg).await?;
            Ok(Arc::new(storage) as Arc<dyn GitStorage>)
        }
    }
}

#[derive(Clone)]
pub struct FilesystemGitStorage {
    root: PathBuf,
}

impl FilesystemGitStorage {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn user_dir(&self, user_id: Uuid) -> PathBuf {
        self.root
            .join("git")
            .join("packs")
            .join(user_id.to_string())
    }

    fn blobs_root(&self) -> PathBuf {
        self.root.join("git").join("blobs")
    }

    fn meta_path(&self, user_id: Uuid, commit_hex: &str) -> PathBuf {
        self.user_dir(user_id).join(format!("{}.json", commit_hex))
    }

    fn pack_path(&self, user_id: Uuid, commit_hex: &str) -> PathBuf {
        self.user_dir(user_id).join(format!("{}.pack", commit_hex))
    }

    fn latest_path(&self, user_id: Uuid) -> PathBuf {
        self.user_dir(user_id).join("latest.json")
    }

    async fn read_meta(&self, path: &Path) -> anyhow::Result<Option<CommitMeta>> {
        if !fs::try_exists(path).await.unwrap_or(false) {
            return Ok(None);
        }
        let mut file = fs::File::open(path).await?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).await?;
        let stored: StoredCommitMeta = serde_json::from_slice(&buf)?;
        Ok(Some(stored.into_meta()?))
    }

    async fn write_meta(&self, path: &Path, meta: &CommitMeta) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let stored = StoredCommitMeta::from_meta(meta);
        let data = serde_json::to_vec_pretty(&stored)?;
        fs::write(path, data).await?;
        Ok(())
    }
}

#[async_trait]
impl GitStorage for FilesystemGitStorage {
    async fn latest_commit(&self, user_id: Uuid) -> anyhow::Result<Option<CommitMeta>> {
        let path = self.latest_path(user_id);
        self.read_meta(path.as_path()).await
    }

    async fn store_pack(
        &self,
        user_id: Uuid,
        pack: &[u8],
        meta: &CommitMeta,
    ) -> anyhow::Result<()> {
        let commit_hex = encode_commit_id(&meta.commit_id);
        let pack_path = self.pack_path(user_id, &commit_hex);
        if let Some(parent) = pack_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&pack_path, pack).await?;
        let meta_path = self.meta_path(user_id, &commit_hex);
        self.write_meta(meta_path.as_path(), meta).await?;
        let latest_path = self.latest_path(user_id);
        self.write_meta(latest_path.as_path(), meta).await
    }

    async fn load_pack_chain(
        &self,
        user_id: Uuid,
        until: Option<&[u8]>,
    ) -> anyhow::Result<PackStream> {
        let storage = self.clone();
        let Some(first_meta) = storage.latest_commit(user_id).await? else {
            return Ok(Box::pin(stream::empty()));
        };
        let until = until.map(|b| b.to_vec());
        let stream = futures_util::stream::try_unfold(
            (storage, user_id, Some(first_meta), until),
            |(storage, user_id, state_opt, until)| async move {
                let current = match state_opt {
                    Some(meta) => meta,
                    None => return Ok(None),
                };
                let commit_hex = encode_commit_id(&current.commit_id);
                let pack_path = storage.pack_path(user_id, &commit_hex);
                if !fs::try_exists(&pack_path).await.unwrap_or(false) {
                    anyhow::bail!("pack not found for commit {}", commit_hex);
                }
                let bytes = fs::read(&pack_path).await?;
                let pack = PackBlob {
                    commit_id: current.commit_id.clone(),
                    bytes,
                    pack_key: current.pack_key.clone(),
                };
                let stop = until
                    .as_ref()
                    .map(|target| target == &current.commit_id)
                    .unwrap_or(false);
                let next_state = if stop {
                    None
                } else if let Some(parent_id) = current.parent_commit_id.clone() {
                    let parent_hex = encode_commit_id(&parent_id);
                    let meta_path = storage.meta_path(user_id, &parent_hex);
                    storage.read_meta(meta_path.as_path()).await?
                } else {
                    None
                };
                Ok(Some((pack, (storage, user_id, next_state, until))))
            },
        );
        Ok(Box::pin(stream))
    }

    async fn put_blob(&self, key: &BlobKey, data: &[u8]) -> anyhow::Result<()> {
        let root = self.blobs_root();
        let path = sanitize_blob_path(root.as_path(), &key.path)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(path, data).await?;
        Ok(())
    }

    async fn fetch_blob(&self, key: &BlobKey) -> anyhow::Result<Vec<u8>> {
        let root = self.blobs_root();
        let path = sanitize_blob_path(root.as_path(), &key.path)?;
        let bytes = fs::read(path).await?;
        Ok(bytes)
    }

    async fn delete_all(&self, user_id: Uuid) -> anyhow::Result<()> {
        let dir = self.user_dir(user_id);
        if fs::try_exists(&dir).await.unwrap_or(false) {
            fs::remove_dir_all(&dir).await?;
        }
        Ok(())
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct StoredCommitMeta {
    commit_id: String,
    parent_commit_id: Option<String>,
    message: Option<String>,
    author_name: Option<String>,
    author_email: Option<String>,
    committed_at: chrono::DateTime<chrono::Utc>,
    pack_key: String,
    file_hash_index: std::collections::HashMap<String, String>,
}

impl StoredCommitMeta {
    fn from_meta(meta: &CommitMeta) -> Self {
        Self {
            commit_id: encode_commit_id(&meta.commit_id),
            parent_commit_id: meta
                .parent_commit_id
                .as_ref()
                .map(|id| encode_commit_id(id)),
            message: meta.message.clone(),
            author_name: meta.author_name.clone(),
            author_email: meta.author_email.clone(),
            committed_at: meta.committed_at,
            pack_key: meta.pack_key.clone(),
            file_hash_index: meta.file_hash_index.clone(),
        }
    }

    fn into_meta(self) -> anyhow::Result<CommitMeta> {
        Ok(CommitMeta {
            commit_id: crate::application::ports::git_storage::decode_commit_id(&self.commit_id)?,
            parent_commit_id: match self.parent_commit_id {
                Some(hex) => Some(crate::application::ports::git_storage::decode_commit_id(
                    &hex,
                )?),
                None => None,
            },
            message: self.message,
            author_name: self.author_name,
            author_email: self.author_email,
            committed_at: self.committed_at,
            pack_key: self.pack_key,
            file_hash_index: self.file_hash_index,
        })
    }
}

fn sanitize_blob_path(root: &Path, key: &str) -> anyhow::Result<PathBuf> {
    use std::path::Component;
    let mut path = root.to_path_buf();
    for component in Path::new(key).components() {
        match component {
            Component::Normal(part) => {
                path.push(part);
            }
            _ => anyhow::bail!("invalid blob key"),
        }
    }
    if !path.starts_with(root) {
        anyhow::bail!("invalid blob path");
    }
    Ok(path)
}

#[derive(Clone)]
pub struct S3GitStorage {
    client: aws_sdk_s3::Client,
    bucket: String,
    root_prefix: String,
    // Mutex to serialize latest pointer updates to avoid race when multiple tasks update latest.json concurrently.
    latest_lock: Arc<Mutex<()>>,
}

impl S3GitStorage {
    pub async fn new(cfg: &Config) -> anyhow::Result<Self> {
        let bucket = cfg
            .s3_bucket
            .clone()
            .context("S3 bucket must be configured for S3 storage backend")?;
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = &cfg.s3_region {
            loader = loader.region(aws_sdk_s3::config::Region::new(region.clone()));
        }
        let shared = loader.load().await;
        let mut builder = aws_sdk_s3::config::Builder::from(&shared);
        if let (Some(access), Some(secret)) = (&cfg.s3_access_key, &cfg.s3_secret_key) {
            let creds = aws_sdk_s3::config::Credentials::new(
                access,
                secret,
                None,
                None,
                "git-storage-static",
            );
            builder = builder.credentials_provider(creds);
        }
        if let Some(endpoint) = &cfg.s3_endpoint {
            builder = builder.endpoint_url(endpoint.clone());
        }
        if cfg.s3_use_path_style {
            builder = builder.force_path_style(true);
        }
        let client = aws_sdk_s3::Client::from_conf(builder.build());
        Ok(Self {
            client,
            bucket,
            root_prefix: cfg.storage_root.clone(),
            latest_lock: Arc::new(Mutex::new(())),
        })
    }

    fn key_for_pack(&self, user_id: Uuid, commit_hex: &str) -> String {
        format!(
            "{}/git/packs/{}/{}.pack",
            self.root_prefix, user_id, commit_hex
        )
    }

    fn key_for_meta(&self, user_id: Uuid, commit_hex: &str) -> String {
        format!(
            "{}/git/packs/{}/{}.json",
            self.root_prefix, user_id, commit_hex
        )
    }

    fn key_for_latest(&self, user_id: Uuid) -> String {
        format!("{}/git/packs/{}/latest.json", self.root_prefix, user_id)
    }

    fn key_for_blob(&self, key: &str) -> String {
        format!("{}/git/blobs/{}", self.root_prefix, key)
    }

    async fn get_object(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(resp) => {
                let mut data = resp.body.into_async_read();
                let mut buf = Vec::new();
                data.read_to_end(&mut buf).await?;
                Ok(Some(buf))
            }
            Err(aws_sdk_s3::error::SdkError::ServiceError(service_err)) => {
                if service_err.err().is_no_such_key() {
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!("failed to fetch {key}: {:?}", service_err))
                }
            }
            Err(err) => Err(anyhow::anyhow!("failed to fetch {key}: {err}")),
        }
    }

    async fn put_object(&self, key: &str, bytes: &[u8]) -> anyhow::Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(aws_sdk_s3::primitives::ByteStream::from(bytes.to_vec()))
            .send()
            .await
            .with_context(|| format!("failed to upload {key}"))?;
        Ok(())
    }

    async fn delete_prefix(&self, prefix: &str) -> anyhow::Result<()> {
        let mut continuation: Option<String> = None;
        loop {
            let mut req = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix);
            if let Some(token) = continuation.as_ref() {
                req = req.continuation_token(token.clone());
            }
            let resp = req.send().await?;
            for obj in resp.contents() {
                if let Some(key) = obj.key() {
                    let _ = self
                        .client
                        .delete_object()
                        .bucket(&self.bucket)
                        .key(key)
                        .send()
                        .await;
                }
            }
            if !resp.is_truncated().unwrap_or(false) {
                break;
            }
            continuation = resp.next_continuation_token().map(|s| s.to_string());
        }
        Ok(())
    }

    async fn fetch_meta(&self, key: &str) -> anyhow::Result<Option<CommitMeta>> {
        let bytes = match self.get_object(key).await? {
            Some(b) => b,
            None => return Ok(None),
        };
        let stored: StoredCommitMeta = serde_json::from_slice(&bytes)?;
        stored.into_meta().map(Some)
    }
}

#[async_trait]
impl GitStorage for S3GitStorage {
    async fn latest_commit(&self, user_id: Uuid) -> anyhow::Result<Option<CommitMeta>> {
        let key = self.key_for_latest(user_id);
        self.fetch_meta(&key).await
    }

    async fn store_pack(
        &self,
        user_id: Uuid,
        pack: &[u8],
        meta: &CommitMeta,
    ) -> anyhow::Result<()> {
        let commit_hex = encode_commit_id(&meta.commit_id);
        let pack_key = self.key_for_pack(user_id, &commit_hex);
        self.put_object(&pack_key, pack).await?;
        let meta_key = self.key_for_meta(user_id, &commit_hex);
        let stored = StoredCommitMeta::from_meta(meta);
        let data = serde_json::to_vec_pretty(&stored)?;
        self.put_object(&meta_key, &data).await?;
        let latest_key = self.key_for_latest(user_id);
        let _guard = self.latest_lock.lock().await;
        self.put_object(&latest_key, &data).await
    }

    async fn load_pack_chain(
        &self,
        user_id: Uuid,
        until: Option<&[u8]>,
    ) -> anyhow::Result<PackStream> {
        let storage = self.clone();
        let Some(first_meta) = storage.latest_commit(user_id).await? else {
            return Ok(Box::pin(stream::empty()));
        };
        let until = until.map(|b| b.to_vec());
        let stream = futures_util::stream::try_unfold(
            (storage, user_id, Some(first_meta), until),
            |(storage, user_id, state_opt, until)| async move {
                let current = match state_opt {
                    Some(meta) => meta,
                    None => return Ok(None),
                };
                let commit_hex = encode_commit_id(&current.commit_id);
                let pack_key = storage.key_for_pack(user_id, &commit_hex);
                let bytes = match storage.get_object(&pack_key).await? {
                    Some(b) => b,
                    None => anyhow::bail!("pack missing for commit {commit_hex}"),
                };
                let pack = PackBlob {
                    commit_id: current.commit_id.clone(),
                    bytes,
                    pack_key: current.pack_key.clone(),
                };
                let stop = until
                    .as_ref()
                    .map(|target| target == &current.commit_id)
                    .unwrap_or(false);
                let next_state = if stop {
                    None
                } else if let Some(parent_id) = current.parent_commit_id.clone() {
                    let parent_hex = encode_commit_id(&parent_id);
                    let meta_key = storage.key_for_meta(user_id, &parent_hex);
                    storage.fetch_meta(&meta_key).await?
                } else {
                    None
                };
                Ok(Some((pack, (storage, user_id, next_state, until))))
            },
        );
        Ok(Box::pin(stream))
    }

    async fn put_blob(&self, key: &BlobKey, data: &[u8]) -> anyhow::Result<()> {
        let key = self.key_for_blob(&key.path);
        self.put_object(&key, data).await
    }

    async fn fetch_blob(&self, key: &BlobKey) -> anyhow::Result<Vec<u8>> {
        let key = self.key_for_blob(&key.path);
        match self.get_object(&key).await? {
            Some(bytes) => Ok(bytes),
            None => anyhow::bail!("blob not found"),
        }
    }

    async fn delete_all(&self, user_id: Uuid) -> anyhow::Result<()> {
        let prefix = format!("{}/git/packs/{}/", self.root_prefix, user_id);
        self.delete_prefix(&prefix).await
    }
}
