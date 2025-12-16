use std::{
    io,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::operation::create_bucket::CreateBucketError;
use aws_sdk_s3::operation::head_bucket::HeadBucketError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{Delete, ObjectIdentifier};
use aws_sdk_s3::{Client, error::SdkError};
use tokio::io::AsyncReadExt;
use uuid::Uuid;

use application::ports::storage_port::{
    StorageProjectionPort, StorageResolverPort, StoredAttachment,
};
use application::utils::hash::sha256_hex;
use crate::db::PgPool;

#[derive(Clone, Debug)]
pub struct S3StorageConfig {
    pub uploads_root: PathBuf,
    pub bucket: String,
    pub region: Option<String>,
    pub endpoint: Option<String>,
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
    pub use_path_style: bool,
}

pub struct S3StoragePort {
    pool: PgPool,
    client: Client,
    bucket: String,
    root: PathBuf,
    root_prefix: String,
}

impl S3StoragePort {
    pub async fn new(pool: PgPool, cfg: &S3StorageConfig) -> anyhow::Result<Self> {
        let bucket = cfg.bucket.clone();

        let mut loader = aws_config::defaults(BehaviorVersion::latest());

        if let Some(region) = &cfg.region {
            loader = loader.region(Region::new(region.clone()));
        }

        let shared_config = loader.load().await;

        let mut builder = aws_sdk_s3::config::Builder::from(&shared_config);

        if let (Some(access), Some(secret)) = (&cfg.access_key, &cfg.secret_key) {
            let creds = Credentials::new(
                access.clone(),
                secret.clone(),
                None,
                None,
                "refmd-s3-static",
            );
            builder = builder.credentials_provider(creds);
        }

        if let Some(endpoint) = &cfg.endpoint {
            builder = builder.endpoint_url(endpoint.clone());
        }

        if cfg.use_path_style {
            builder = builder.force_path_style(true);
        }

        let client = Client::from_conf(builder.build());

        let root = cfg.uploads_root.clone();
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
        let rel = crate::storage::relative_from_uploads(&self.root, abs_path)
            .replace('\\', "/");
        self.relative_to_key(&rel)
    }

    async fn put_object(&self, key: &str, data: &[u8]) -> anyhow::Result<()> {
        let body = ByteStream::from(data.to_vec());
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(body)
            .send()
            .await
            .with_context(|| format!("failed to upload object {key}"))?;
        Ok(())
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

        let row = sqlx::query(
            "SELECT owner_id, type, path, desired_path, archived_at FROM documents WHERE id = $1",
        )
        .bind(doc_id)
        .fetch_optional(&self.pool)
        .await?;
        let row = match row {
            Some(row) => row,
            None => return Ok(()),
        };
        let owner_id: Uuid = row.get("owner_id");
        let dtype: String = row.get("type");
        if dtype == "folder" {
            return Ok(());
        }
        let old_rel: Option<String> = row.try_get("path").ok();

        let desired_path: String = row.get("desired_path");
        let archived = row
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("archived_at")
            .ok()
            .flatten()
            .is_some();
        let target_rel = crate::storage::owner_relative_from_desired(
            owner_id,
            &desired_path,
            archived,
        );
        let target_parent_rel = crate::storage::owner_relative_parent_from_desired(
            owner_id,
            &desired_path,
            archived,
        );

        if let Some(old_rel) = old_rel.clone() {
            if old_rel != target_rel {
                let src_key = self.relative_to_key(&old_rel);
                let dst_key = self.relative_to_key(&target_rel);
                if self.object_exists(&src_key).await? {
                    self.copy_object(&src_key, &dst_key).await?;
                    self.delete_object(&src_key).await?;
                }
                let _ = crate::storage::mark_dirty_delete_relative(
                    &self.pool, &old_rel,
                )
                .await;
            }
        }

        let new_dir = self.root.join(&target_parent_rel);

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
                    crate::storage::relative_from_uploads(&self.root, &new_path)
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
                let _ = crate::storage::mark_dirty_delete_relative(
                    &self.pool, &old_path,
                )
                .await;
                let _ = crate::storage::mark_dirty_upsert_relative(
                    &self.pool,
                    &new_rel_attachment,
                    false,
                    None,
                )
                .await;
            }
        }

        // Avoid touching updated_at for background projection moves; user edits already
        // advance the timestamp when the path/metadata actually changes.
        sqlx::query("UPDATE documents SET path = $2 WHERE id = $1")
            .bind(doc_id)
            .bind(&target_rel)
            .execute(&self.pool)
            .await?;

        let _ = crate::storage::mark_dirty_upsert_relative(
            &self.pool,
            &target_rel,
            true,
            None,
        )
        .await;

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

fn sanitize_filename(name: &str) -> String {
    let mut s = name.trim().to_string();
    let invalid = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\0'];
    for ch in invalid {
        s = s.replace(ch, "-");
    }
    if s.is_empty() {
        s = "attachment".into();
    }
    if s.len() > 120 {
        s.truncate(120);
    }
    s
}

#[async_trait]
impl StorageProjectionPort for S3StoragePort {
    async fn move_folder_subtree(&self, folder_id: Uuid) -> anyhow::Result<usize> {
        let ids =
            crate::storage::list_descendant_docs(&self.pool, folder_id).await?;
        for id in &ids {
            self.move_doc_paths(*id).await?;
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
            crate::storage::list_descendant_docs(&self.pool, folder_id).await?;
        for id in &ids {
            self.delete_doc_physical(*id).await?;
        }
        Ok(ids.len())
    }

    async fn sync_doc_paths(&self, doc_id: Uuid) -> anyhow::Result<()> {
        self.move_doc_paths(doc_id).await
    }

    async fn delete_relative_path(&self, rel: &str) -> anyhow::Result<()> {
        let key = self.relative_to_key(rel);
        let _ = self.delete_object(&key).await;
        crate::storage::mark_dirty_delete_relative(&self.pool, rel).await?;
        Ok(())
    }
}

#[async_trait]
impl StorageResolverPort for S3StoragePort {
    async fn build_doc_dir(&self, doc_id: Uuid) -> anyhow::Result<PathBuf> {
        crate::storage::build_doc_dir(&self.pool, &self.root, doc_id).await
    }

    async fn build_doc_file_path(&self, doc_id: Uuid) -> anyhow::Result<PathBuf> {
        crate::storage::build_doc_file_path(&self.pool, &self.root, doc_id).await
    }

    fn relative_from_uploads(&self, abs: &Path) -> String {
        crate::storage::relative_from_uploads(&self.root, abs).replace('\\', "/")
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

    async fn resolve_upload_path(&self, doc_id: Uuid, rest_path: &str) -> anyhow::Result<PathBuf> {
        let doc_dir = crate::storage::build_doc_dir(&self.pool, &self.root, doc_id)
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

        let rel = crate::storage::relative_from_uploads(&self.root, &full_path)
            .replace('\\', "/");
        let key = self.relative_to_key(&rel);
        if !self.object_exists(&key).await? {
            anyhow::bail!("not_found");
        }
        Ok(full_path)
    }

    async fn read_bytes(&self, abs_path: &Path) -> anyhow::Result<Vec<u8>> {
        let key = self.key_from_path(abs_path);
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await;

        let object = match resp {
            Ok(obj) => obj,
            Err(SdkError::ServiceError(service_err)) => {
                if service_err.err().is_no_such_key() {
                    let err =
                        io::Error::new(io::ErrorKind::NotFound, format!("object {key} not found"));
                    return Err(err.into());
                }
                return Err(anyhow!("failed to get object {key}: {}", service_err.err()));
            }
            Err(err) => {
                return Err(anyhow!("failed to get object {key}: {err}"));
            }
        };

        let mut reader = object.body.into_async_read();
        let mut data = Vec::new();
        reader.read_to_end(&mut data).await?;
        Ok(data)
    }

    async fn exists(&self, abs_path: &Path) -> anyhow::Result<bool> {
        let key = self.key_from_path(abs_path);
        self.object_exists(&key).await
    }

    async fn write_bytes(&self, abs_path: &Path, data: &[u8]) -> anyhow::Result<()> {
        if let Some(parent) = abs_path.parent() {
            tokio::fs::create_dir_all(parent).await.ok();
        }
        let key = self.key_from_path(abs_path);
        self.put_object(&key, data).await?;
        let rel = crate::storage::relative_from_uploads(&self.root, abs_path)
            .replace('\\', "/");
        let _ = crate::storage::mark_dirty_upsert_relative(
            &self.pool, &rel, true, None,
        )
        .await;
        Ok(())
    }

    async fn store_doc_attachment(
        &self,
        doc_id: Uuid,
        original_filename: Option<&str>,
        bytes: &[u8],
    ) -> anyhow::Result<StoredAttachment> {
        use tokio::fs;

        let base_dir =
            crate::storage::build_doc_dir(&self.pool, &self.root, doc_id)
                .await?
                .to_path_buf();
        let attachments_dir = base_dir.join("attachments");
        let _ = fs::create_dir_all(&attachments_dir).await;

        let sanitized = sanitize_filename(original_filename.unwrap_or("attachment"));
        let mut target = attachments_dir.join(&sanitized);
        let mut relative =
            crate::storage::relative_from_uploads(&self.root, &target)
                .replace('\\', "/");
        let mut counter = 1;
        loop {
            let key = self.relative_to_key(&relative);
            if !self.object_exists(&key).await? {
                break;
            }
            let stem = target
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("attachment");
            let ext = target
                .extension()
                .and_then(|s| s.to_str())
                .filter(|s| !s.is_empty())
                .map(|s| format!(".{s}"))
                .unwrap_or_default();
            let new_name = format!("{stem}-{counter}{ext}");
            target = attachments_dir.join(&new_name);
            relative = crate::storage::relative_from_uploads(&self.root, &target)
                .replace('\\', "/");
            counter += 1;
        }

        if let Some(parent) = target.parent() {
            let _ = fs::create_dir_all(parent).await;
        }
        let key = self.relative_to_key(&relative);
        self.put_object(&key, bytes).await?;
        let size = bytes.len() as i64;
        let hash = sha256_hex(bytes);
        Ok(StoredAttachment {
            filename: target
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("attachment")
                .to_string(),
            relative_path: relative,
            size,
            content_hash: hash,
        })
    }
}

impl S3StoragePort {
    #[allow(dead_code)]
    async fn delete_children_with_prefix(&self, rel: &str) -> anyhow::Result<()> {
        let mut key_prefix = self.relative_to_key(rel);
        if key_prefix.is_empty() {
            return Ok(());
        }
        if !key_prefix.ends_with('/') {
            key_prefix.push('/');
        }
        let mut token: Option<String> = None;
        loop {
            let resp = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&key_prefix)
                .set_continuation_token(token.clone())
                .send()
                .await?;
            let objects: Vec<_> = resp
                .contents()
                .iter()
                .filter_map(|obj| {
                    obj.key()
                        .and_then(|key| ObjectIdentifier::builder().key(key).build().ok())
                })
                .collect();
            if !objects.is_empty() {
                self.client
                    .delete_objects()
                    .bucket(&self.bucket)
                    .delete(Delete::builder().set_objects(Some(objects)).build()?)
                    .send()
                    .await?;
            }
            if let Some(next) = resp.next_continuation_token() {
                token = Some(next.to_string());
            } else {
                break;
            }
        }
        Ok(())
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
