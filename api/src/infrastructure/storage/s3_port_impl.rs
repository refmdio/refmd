use std::path::{Component, Path, PathBuf};

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::operation::create_bucket::CreateBucketError;
use aws_sdk_s3::operation::head_bucket::HeadBucketError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::{Client, error::SdkError};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use uuid::Uuid;

use crate::application::ports::storage_port::{StoragePort, StoredAttachment};
use crate::bootstrap::config::Config;
use crate::infrastructure::db::PgPool;

pub struct S3StoragePort {
    pool: PgPool,
    client: Client,
    bucket: String,
    root: PathBuf,
    root_prefix: String,
}

impl S3StoragePort {
    pub async fn new(pool: PgPool, cfg: &Config) -> anyhow::Result<Self> {
        let bucket = cfg
            .s3_bucket
            .clone()
            .context("S3 bucket must be configured when using S3 storage backend")?;

        let mut loader = aws_config::defaults(BehaviorVersion::latest());

        if let Some(region) = &cfg.s3_region {
            loader = loader.region(Region::new(region.clone()));
        }

        let shared_config = loader.load().await;

        let mut builder = aws_sdk_s3::config::Builder::from(&shared_config);

        if let (Some(access), Some(secret)) = (&cfg.s3_access_key, &cfg.s3_secret_key) {
            let creds = Credentials::new(
                access.clone(),
                secret.clone(),
                None,
                None,
                "refmd-s3-static",
            );
            builder = builder.credentials_provider(creds);
        }

        if let Some(endpoint) = &cfg.s3_endpoint {
            builder = builder.endpoint_url(endpoint.clone());
        }

        if cfg.s3_use_path_style {
            builder = builder.force_path_style(true);
        }

        let client = Client::from_conf(builder.build());

        let root = PathBuf::from(&cfg.storage_root);
        let root_prefix = normalize_prefix(&root);

        ensure_bucket(&client, &bucket).await?;

        Ok(Self {
            pool,
            client,
            bucket,
            root,
            root_prefix,
        })
    }

    fn relative_to_key(&self, relative: &str) -> String {
        let rel = relative.trim_start_matches('/');
        if self.root_prefix.is_empty() {
            rel.to_string()
        } else if rel.is_empty() {
            self.root_prefix.clone()
        } else {
            format!("{}/{}", self.root_prefix, rel)
        }
    }

    fn key_from_path(&self, abs_path: &Path) -> String {
        let rel = crate::infrastructure::storage::relative_from_uploads(&self.root, abs_path)
            .replace('\\', "/");
        self.relative_to_key(&rel)
    }

    async fn object_exists(&self, key: &str) -> anyhow::Result<bool> {
        use aws_sdk_s3::error::SdkError;
        use aws_sdk_s3::operation::head_object::HeadObjectError;

        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(err) => match err {
                SdkError::ServiceError(service_err) => {
                    let head_err: &HeadObjectError = service_err.err();
                    if head_err.is_not_found() {
                        Ok(false)
                    } else {
                        Err(anyhow!("head_object error for {}: {}", key, head_err))
                    }
                }
                other => Err(anyhow!("head_object failed for {}: {}", key, other)),
            },
        }
    }

    async fn copy_object(&self, src_key: &str, dst_key: &str) -> anyhow::Result<()> {
        if src_key == dst_key {
            return Ok(());
        }
        let copy_source = format!("{}/{}", &self.bucket, src_key);
        self.client
            .copy_object()
            .bucket(&self.bucket)
            .key(dst_key)
            .copy_source(urlencoding::encode(&copy_source))
            .send()
            .await
            .with_context(|| format!("failed to copy {src_key} to {dst_key}"))?;
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(src_key)
            .send()
            .await
            .with_context(|| format!("failed to delete source object {src_key}"))?;
        Ok(())
    }

    async fn delete_object(&self, key: &str) -> anyhow::Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .with_context(|| format!("failed to delete object {key}"))?;
        Ok(())
    }

    async fn move_doc_paths(&self, doc_id: Uuid) -> anyhow::Result<()> {
        use sqlx::Row;

        let row = sqlx::query("SELECT type, path FROM documents WHERE id = $1")
            .bind(doc_id)
            .fetch_optional(&self.pool)
            .await?;
        let row = match row {
            Some(row) => row,
            None => return Ok(()),
        };
        let dtype: String = row.get("type");
        if dtype == "folder" {
            return Ok(());
        }
        let old_rel: Option<String> = row.try_get("path").ok();

        let new_full =
            crate::infrastructure::storage::build_doc_file_path(&self.pool, &self.root, doc_id)
                .await?;
        let new_rel = crate::infrastructure::storage::relative_from_uploads(&self.root, &new_full)
            .replace('\\', "/");

        if let Some(old_rel) = old_rel.clone() {
            if old_rel != new_rel {
                let src_key = self.relative_to_key(&old_rel);
                let dst_key = self.relative_to_key(&new_rel);
                if self.object_exists(&src_key).await? {
                    self.copy_object(&src_key, &dst_key).await?;
                    self.delete_object(&src_key).await?;
                }
            }
        }

        let new_dir = new_full
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| self.root.clone());

        let files = sqlx::query("SELECT filename, storage_path FROM files WHERE document_id = $1")
            .bind(doc_id)
            .fetch_all(&self.pool)
            .await?;

        if !files.is_empty() {
            let dst_attachments = new_dir.join("attachments");
            for row in files {
                let filename: String = row.get("filename");
                let old_path: String = row.get("storage_path");
                let new_path = dst_attachments.join(&filename);
                let new_rel_attachment =
                    crate::infrastructure::storage::relative_from_uploads(&self.root, &new_path)
                        .replace('\\', "/");
                if old_path != new_rel_attachment {
                    let src_key = self.relative_to_key(&old_path);
                    let dst_key = self.relative_to_key(&new_rel_attachment);
                    if self.object_exists(&src_key).await? {
                        self.copy_object(&src_key, &dst_key).await?;
                        self.delete_object(&src_key).await?;
                    }
                    sqlx::query(
                        "UPDATE files SET storage_path = $2 WHERE document_id = $1 AND filename = $3",
                    )
                    .bind(doc_id)
                    .bind(&new_rel_attachment)
                    .bind(&filename)
                    .execute(&self.pool)
                    .await?;
                }
            }
        }

        sqlx::query("UPDATE documents SET path = $2, updated_at = now() WHERE id = $1")
            .bind(doc_id)
            .bind(&new_rel)
            .execute(&self.pool)
            .await?;

        Ok(())
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

#[async_trait]
impl StoragePort for S3StoragePort {
    async fn move_folder_subtree(&self, folder_id: Uuid) -> anyhow::Result<usize> {
        let ids =
            crate::infrastructure::storage::list_descendant_docs(&self.pool, folder_id).await?;
        for id in &ids {
            let _ = self.move_doc_paths(*id).await;
        }
        Ok(ids.len())
    }

    async fn delete_doc_physical(&self, doc_id: Uuid) -> anyhow::Result<()> {
        use sqlx::Row;

        let row = sqlx::query("SELECT type, path FROM documents WHERE id = $1")
            .bind(doc_id)
            .fetch_optional(&self.pool)
            .await?;
        let row = match row {
            Some(r) => r,
            None => return Ok(()),
        };
        let dtype: String = row.get("type");
        if dtype == "folder" {
            return Ok(());
        }
        if let Some(path) = row.try_get::<String, _>("path").ok() {
            let key = self.relative_to_key(&path);
            let _ = self.delete_object(&key).await;
        }

        let attachments = sqlx::query("SELECT storage_path FROM files WHERE document_id = $1")
            .bind(doc_id)
            .fetch_all(&self.pool)
            .await?;
        for row in attachments {
            if let Ok(storage_path) = row.try_get::<String, _>("storage_path") {
                let key = self.relative_to_key(&storage_path);
                let _ = self.delete_object(&key).await;
            }
        }
        Ok(())
    }

    async fn delete_folder_physical(&self, folder_id: Uuid) -> anyhow::Result<usize> {
        let ids =
            crate::infrastructure::storage::list_descendant_docs(&self.pool, folder_id).await?;
        for id in &ids {
            let _ = self.delete_doc_physical(*id).await;
        }
        Ok(ids.len())
    }

    async fn build_doc_dir(&self, doc_id: Uuid) -> anyhow::Result<PathBuf> {
        crate::infrastructure::storage::build_doc_dir(&self.pool, &self.root, doc_id).await
    }

    async fn build_doc_file_path(&self, doc_id: Uuid) -> anyhow::Result<PathBuf> {
        crate::infrastructure::storage::build_doc_file_path(&self.pool, &self.root, doc_id).await
    }

    fn relative_from_uploads(&self, abs: &Path) -> String {
        crate::infrastructure::storage::relative_from_uploads(&self.root, abs).replace('\\', "/")
    }

    fn user_repo_dir(&self, user_id: Uuid) -> String {
        let rel = format!("{}", user_id);
        if self.root_prefix.is_empty() {
            rel
        } else {
            format!("{}/{}", self.root_prefix, rel)
        }
    }

    fn absolute_from_relative(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    async fn sync_doc_paths(&self, doc_id: Uuid) -> anyhow::Result<()> {
        self.move_doc_paths(doc_id).await
    }

    async fn resolve_upload_path(&self, doc_id: Uuid, rest_path: &str) -> anyhow::Result<PathBuf> {
        let doc_dir = crate::infrastructure::storage::build_doc_dir(&self.pool, &self.root, doc_id)
            .await?
            .to_path_buf();
        if !doc_dir.starts_with(&self.root) {
            anyhow::bail!("forbidden");
        }

        let mut relative = PathBuf::new();
        for component in Path::new(rest_path).components() {
            match component {
                Component::Normal(part) => relative.push(part),
                Component::CurDir => continue,
                _ => anyhow::bail!("forbidden"),
            }
        }
        if relative.as_os_str().is_empty() {
            anyhow::bail!("forbidden");
        }

        let full_path = doc_dir.join(&relative);
        if !full_path.starts_with(&self.root) {
            anyhow::bail!("forbidden");
        }

        let rel = crate::infrastructure::storage::relative_from_uploads(&self.root, &full_path)
            .replace('\\', "/");
        let key = self.relative_to_key(&rel);
        if !self.object_exists(&key).await? {
            anyhow::bail!("not_found");
        }
        Ok(full_path)
    }

    async fn read_bytes(&self, abs_path: &Path) -> anyhow::Result<Vec<u8>> {
        let key = self.key_from_path(abs_path);
        let object = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .context("failed to get object")?;
        let mut reader = object.body.into_async_read();
        let mut data = Vec::new();
        reader.read_to_end(&mut data).await?;
        Ok(data)
    }

    async fn write_bytes(&self, abs_path: &Path, data: &[u8]) -> anyhow::Result<()> {
        let relative = crate::infrastructure::storage::relative_from_uploads(&self.root, abs_path)
            .replace('\\', "/");
        let key = self.relative_to_key(&relative);
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(ByteStream::from(data.to_vec()))
            .send()
            .await
            .with_context(|| format!("failed to upload object {key}"))?;
        Ok(())
    }

    async fn store_doc_attachment(
        &self,
        doc_id: Uuid,
        original_filename: Option<&str>,
        bytes: &[u8],
    ) -> anyhow::Result<StoredAttachment> {
        let base_dir =
            crate::infrastructure::storage::build_doc_dir(&self.pool, &self.root, doc_id).await?;
        let attachments_dir = base_dir.join("attachments");

        let original = original_filename.unwrap_or("file.bin");
        let mut safe = crate::infrastructure::storage::sanitize_title(original);

        let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let (stem, ext) = {
            let p = Path::new(&safe);
            let stem = p
                .file_stem()
                .and_then(|s| s.to_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("file")
                .to_string();
            let ext = p
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            (stem, ext)
        };

        safe = if ext.is_empty() {
            format!("{}_{}", stem, ts)
        } else {
            format!("{}_{}.{}", stem, ts, ext)
        };

        let mut candidate = attachments_dir.join(&safe);
        let mut counter = 1;
        loop {
            let relative =
                crate::infrastructure::storage::relative_from_uploads(&self.root, &candidate)
                    .replace('\\', "/");
            let key = self.relative_to_key(&relative);
            if !self.object_exists(&key).await? {
                break;
            }
            let p = Path::new(&safe);
            let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
            let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
            let new_name = if ext.is_empty() {
                format!("{}-{}", stem, counter)
            } else {
                format!("{}-{}.{}", stem, counter, ext)
            };
            candidate = attachments_dir.join(&new_name);
            safe = new_name;
            counter += 1;
        }

        let relative =
            crate::infrastructure::storage::relative_from_uploads(&self.root, &candidate)
                .replace('\\', "/");
        let key = self.relative_to_key(&relative);

        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let content_hash = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(ByteStream::from(bytes.to_vec()))
            .send()
            .await
            .with_context(|| format!("failed to upload object {key}"))?;

        Ok(StoredAttachment {
            filename: safe,
            relative_path: relative,
            size: bytes.len() as i64,
            content_hash,
        })
    }
}

async fn ensure_bucket(client: &Client, bucket: &str) -> anyhow::Result<()> {
    match client.head_bucket().bucket(bucket).send().await {
        Ok(_) => return Ok(()),
        Err(SdkError::ServiceError(service_err)) => {
            if !matches!(service_err.err(), HeadBucketError::NotFound(_)) {
                return Err(anyhow!(service_err.err().to_string()));
            }
        }
        Err(err) => return Err(anyhow!(err.to_string())),
    }

    match client.create_bucket().bucket(bucket).send().await {
        Ok(_) => Ok(()),
        Err(SdkError::ServiceError(service_err)) => match service_err.err() {
            CreateBucketError::BucketAlreadyOwnedByYou(_) => Ok(()),
            CreateBucketError::BucketAlreadyExists(_) => Ok(()),
            other => Err(anyhow!(other.to_string())),
        },
        Err(err) => Err(anyhow!(err.to_string())),
    }
}
