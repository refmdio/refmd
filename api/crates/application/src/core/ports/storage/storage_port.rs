use async_trait::async_trait;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

#[derive(Debug, Clone)]
pub struct StoredAttachment {
    pub filename: String,
    pub relative_path: String,
    pub size: i64,
    pub content_hash: String,
}

#[async_trait]
pub trait StorageResolverPort: Send + Sync {
    async fn build_doc_dir(&self, doc_id: Uuid) -> PortResult<PathBuf>;
    async fn build_doc_file_path(&self, doc_id: Uuid) -> PortResult<PathBuf>;
    fn relative_from_uploads(&self, abs: &Path) -> String;
    fn user_repo_dir(&self, user_id: Uuid) -> String;
    fn absolute_from_relative(&self, rel: &str) -> PathBuf;
    async fn resolve_upload_path(&self, doc_id: Uuid, rest_path: &str) -> PortResult<PathBuf>;
    async fn read_bytes(&self, abs_path: &Path) -> PortResult<Vec<u8>>;
    async fn exists(&self, abs_path: &Path) -> PortResult<bool>;
    async fn write_bytes(&self, abs_path: &Path, data: &[u8]) -> PortResult<()>;
    async fn store_doc_attachment(
        &self,
        doc_id: Uuid,
        original_filename: Option<&str>,
        bytes: &[u8],
    ) -> PortResult<StoredAttachment>;

    // --- Public file storage (for E2EE decrypted files) ---

    /// Store a public (decrypted) file for a published document
    /// Returns the storage path: public/{workspace_id}/{document_id}/{file_id}
    async fn store_public_file(
        &self,
        workspace_id: Uuid,
        document_id: Uuid,
        file_id: Uuid,
        bytes: &[u8],
    ) -> PortResult<String>;

    /// Read a public file
    async fn read_public_file(
        &self,
        workspace_id: Uuid,
        document_id: Uuid,
        file_id: Uuid,
    ) -> PortResult<Vec<u8>>;

    /// Delete a public file
    async fn delete_public_file(
        &self,
        workspace_id: Uuid,
        document_id: Uuid,
        file_id: Uuid,
    ) -> PortResult<()>;

    /// Delete all public files for a document
    async fn delete_public_files_for_document(
        &self,
        workspace_id: Uuid,
        document_id: Uuid,
    ) -> PortResult<()>;
}

#[async_trait]
pub trait StorageProjectionPort: Send + Sync {
    async fn move_folder_subtree(&self, folder_id: Uuid) -> PortResult<usize>;
    async fn delete_doc_physical(&self, doc_id: Uuid) -> PortResult<()>;
    async fn delete_folder_physical(&self, folder_id: Uuid) -> PortResult<usize>;
    async fn sync_doc_paths(&self, doc_id: Uuid) -> PortResult<()>;
    async fn delete_relative_path(&self, rel: &str) -> PortResult<()>;
}
