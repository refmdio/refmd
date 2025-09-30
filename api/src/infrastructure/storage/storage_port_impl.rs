use std::fmt::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::application::ports::storage_port::{StoragePort, StoredAttachment};
use sha2::{Digest, Sha256};

pub struct FsStoragePort {
    pub pool: crate::infrastructure::db::PgPool,
    pub uploads_root: PathBuf,
}

#[async_trait::async_trait]
impl StoragePort for FsStoragePort {
    async fn move_folder_subtree(&self, folder_id: Uuid) -> anyhow::Result<usize> {
        crate::infrastructure::storage::move_folder_subtree(
            &self.pool,
            self.uploads_root.as_path(),
            folder_id,
        )
        .await
    }

    async fn delete_doc_physical(&self, doc_id: Uuid) -> anyhow::Result<()> {
        crate::infrastructure::storage::delete_doc_physical(
            &self.pool,
            self.uploads_root.as_path(),
            doc_id,
        )
        .await
    }

    async fn delete_folder_physical(&self, folder_id: Uuid) -> anyhow::Result<usize> {
        crate::infrastructure::storage::delete_folder_physical(
            &self.pool,
            self.uploads_root.as_path(),
            folder_id,
        )
        .await
    }

    async fn build_doc_dir(&self, doc_id: Uuid) -> anyhow::Result<PathBuf> {
        crate::infrastructure::storage::build_doc_dir(
            &self.pool,
            self.uploads_root.as_path(),
            doc_id,
        )
        .await
    }

    async fn build_doc_file_path(&self, doc_id: Uuid) -> anyhow::Result<PathBuf> {
        crate::infrastructure::storage::build_doc_file_path(
            &self.pool,
            self.uploads_root.as_path(),
            doc_id,
        )
        .await
    }

    fn relative_from_uploads(&self, abs: &Path) -> String {
        crate::infrastructure::storage::relative_from_uploads(self.uploads_root.as_path(), abs)
    }

    fn user_repo_dir(&self, user_id: Uuid) -> String {
        let path = self.uploads_root.join(user_id.to_string());
        path.to_string_lossy().to_string()
    }

    fn absolute_from_relative(&self, rel: &str) -> PathBuf {
        self.uploads_root.join(rel)
    }

    async fn sync_doc_paths(&self, doc_id: Uuid) -> anyhow::Result<()> {
        crate::infrastructure::storage::move_doc_paths(
            &self.pool,
            self.uploads_root.as_path(),
            doc_id,
        )
        .await
    }

    async fn resolve_upload_path(&self, doc_id: Uuid, rest_path: &str) -> anyhow::Result<PathBuf> {
        use std::path::Component;
        use tokio::fs;

        // Build base directory for the document (guaranteed to live under uploads dir).
        let doc_dir = crate::infrastructure::storage::build_doc_dir(
            &self.pool,
            self.uploads_root.as_path(),
            doc_id,
        )
        .await?;
        let uploads_root = self.uploads_root.as_path();

        if !doc_dir.starts_with(uploads_root) {
            anyhow::bail!("forbidden");
        }

        // Normalise the rest path and reject any traversal attempts.
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

        let full_path = doc_dir.join(relative);
        if !full_path.starts_with(uploads_root) {
            anyhow::bail!("forbidden");
        }

        if !fs::try_exists(&full_path).await.unwrap_or(false) {
            anyhow::bail!("not_found");
        }

        Ok(full_path)
    }

    async fn read_bytes(&self, abs_path: &Path) -> anyhow::Result<Vec<u8>> {
        let data = tokio::fs::read(abs_path).await?;
        Ok(data)
    }

    async fn write_bytes(&self, abs_path: &Path, data: &[u8]) -> anyhow::Result<()> {
        if let Some(parent) = abs_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(abs_path, data).await?;
        Ok(())
    }

    async fn store_doc_attachment(
        &self,
        doc_id: Uuid,
        original_filename: Option<&str>,
        bytes: &[u8],
    ) -> anyhow::Result<StoredAttachment> {
        use tokio::fs;

        let base_dir = crate::infrastructure::storage::build_doc_dir(
            &self.pool,
            self.uploads_root.as_path(),
            doc_id,
        )
        .await?;
        let attachments_dir = base_dir.join("attachments");
        let _ = fs::create_dir_all(&attachments_dir).await;

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
        while fs::try_exists(&candidate).await.unwrap_or(false) {
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

        fs::write(&candidate, bytes).await?;
        let relative = crate::infrastructure::storage::relative_from_uploads(
            self.uploads_root.as_path(),
            &candidate,
        )
        .replace('\\', "/");
        let size = bytes.len() as i64;

        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut content_hash = String::with_capacity(64);
        for byte in digest {
            let _ = write!(&mut content_hash, "{:02x}", byte);
        }

        Ok(StoredAttachment {
            filename: safe,
            relative_path: relative,
            size,
            content_hash,
        })
    }
}
