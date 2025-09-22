use async_trait::async_trait;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct StoredAttachment {
    pub filename: String,
    pub absolute_path: PathBuf,
    pub relative_path: String,
    pub size: i64,
}

#[async_trait]
pub trait StoragePort: Send + Sync {
    async fn move_folder_subtree(&self, folder_id: Uuid) -> anyhow::Result<usize>;
    async fn delete_doc_physical(&self, doc_id: Uuid) -> anyhow::Result<()>;
    async fn delete_folder_physical(&self, folder_id: Uuid) -> anyhow::Result<usize>;
    async fn build_doc_dir(&self, doc_id: Uuid) -> anyhow::Result<PathBuf>;
    async fn build_doc_file_path(&self, doc_id: Uuid) -> anyhow::Result<PathBuf>;
    fn relative_from_uploads(&self, abs: &Path) -> String;
    fn user_repo_dir(&self, user_id: Uuid) -> String;
    async fn resolve_upload_path(&self, doc_id: Uuid, rest_path: &str) -> anyhow::Result<PathBuf>;
    async fn read_bytes(&self, abs_path: &Path) -> anyhow::Result<Vec<u8>>;
    async fn store_doc_attachment(
        &self,
        doc_id: Uuid,
        original_filename: Option<&str>,
        bytes: &[u8],
    ) -> anyhow::Result<StoredAttachment>;
}
