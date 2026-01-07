use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

#[derive(Debug, Clone)]
pub struct FileMeta {
    pub storage_path: String,
    pub content_type: Option<String>,
    pub document_id: Uuid,
    pub workspace_id: Uuid,
    // E2EE fields
    pub encrypted_metadata: Option<Vec<u8>>,
    pub encrypted_metadata_nonce: Option<Vec<u8>>,
    pub encrypted_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FilePathMeta {
    pub storage_path: String,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StoredFileScope {
    pub file_id: Uuid,
    pub document_id: Uuid,
    pub workspace_id: Uuid,
}

#[async_trait]
pub trait FilesRepository: Send + Sync {
    async fn is_workspace_document(&self, doc_id: Uuid, workspace_id: Uuid) -> PortResult<bool>;

    /// Insert a file with optional E2EE metadata.
    /// For plaintext files: pass encrypted_* fields as None
    /// For E2EE files: pass encrypted_* fields with values
    async fn insert_file(&self, input: FileInsert<'_>) -> PortResult<Uuid>;

    async fn get_file_meta(&self, file_id: Uuid) -> PortResult<Option<FileMeta>>;
    async fn get_file_path_by_doc_and_name(
        &self,
        doc_id: Uuid,
        filename: &str,
    ) -> PortResult<Option<FilePathMeta>>;

    async fn list_storage_paths_for_document(&self, doc_id: Uuid) -> PortResult<Vec<String>>;

    async fn list_files_for_document(&self, doc_id: Uuid) -> PortResult<Vec<FileRecord>>;

    async fn list_storage_paths_for_workspace(&self, workspace_id: Uuid)
    -> PortResult<Vec<String>>;

    async fn find_by_storage_path(&self, storage_path: &str)
    -> PortResult<Option<StoredFileScope>>;

    async fn update_storage_path(&self, file_id: Uuid, storage_path: &str) -> PortResult<()>;

    async fn update_hash_and_size(
        &self,
        file_id: Uuid,
        size: i64,
        content_hash: &str,
    ) -> PortResult<()>;

    async fn delete_by_id(&self, file_id: Uuid) -> PortResult<()>;
}

#[async_trait]
pub trait FilesRepositoryTx: Send {
    async fn list_storage_paths_for_document(&mut self, doc_id: Uuid) -> PortResult<Vec<String>>;
}

#[derive(Debug, Clone)]
pub struct FileRecord {
    pub id: Uuid,
    pub filename: String,
    pub content_type: Option<String>,
    pub size: i64,
    pub storage_path: String,
    pub content_hash: String,
    // E2EE fields
    pub encrypted_metadata: Option<Vec<u8>>,
    pub encrypted_metadata_nonce: Option<Vec<u8>>,
    pub encrypted_hash: Option<String>,
}

/// Input for file insert (unified for both plaintext and E2EE)
#[derive(Debug, Clone)]
pub struct FileInsert<'a> {
    pub doc_id: Uuid,
    pub filename: &'a str,
    pub content_type: Option<&'a str>,
    pub size: i64,
    pub storage_path: &'a str,
    pub content_hash: &'a str,
    /// E2EE: encrypted file metadata
    pub encrypted_metadata: Option<&'a [u8]>,
    /// E2EE: nonce for encrypted metadata
    pub encrypted_metadata_nonce: Option<&'a [u8]>,
    /// E2EE: encrypted hash of the file content
    pub encrypted_hash: Option<&'a str>,
}
