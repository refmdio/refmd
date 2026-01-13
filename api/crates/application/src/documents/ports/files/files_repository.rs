use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

#[derive(Debug, Clone)]
pub struct FileMeta {
    pub storage_path: String,
    pub document_id: Uuid,
    pub workspace_id: Uuid,
    /// Encrypted file metadata (filename, content_type, etc.)
    /// None for legacy files uploaded before E2EE
    pub encrypted_metadata: Option<Vec<u8>>,
    /// Nonce for encrypted metadata
    /// None for legacy files uploaded before E2EE
    pub encrypted_metadata_nonce: Option<Vec<u8>>,
    /// Hash of encrypted content
    /// None for legacy files uploaded before E2EE
    pub encrypted_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FilePathMeta {
    pub storage_path: String,
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

    /// Insert a file record
    async fn insert_file(&self, input: FileInsert<'_>) -> PortResult<Uuid>;

    async fn get_file_meta(&self, file_id: Uuid) -> PortResult<Option<FileMeta>>;

    async fn list_storage_paths_for_document(&self, doc_id: Uuid) -> PortResult<Vec<String>>;

    async fn list_files_for_document(&self, doc_id: Uuid) -> PortResult<Vec<FileRecord>>;

    async fn list_storage_paths_for_workspace(&self, workspace_id: Uuid)
    -> PortResult<Vec<String>>;

    async fn find_by_storage_path(&self, storage_path: &str)
    -> PortResult<Option<StoredFileScope>>;

    async fn update_storage_path(&self, file_id: Uuid, storage_path: &str) -> PortResult<()>;

    async fn update_size_and_hash(
        &self,
        file_id: Uuid,
        size: i64,
        encrypted_hash: &str,
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
    pub size: i64,
    pub storage_path: String,
    /// Encrypted file metadata (filename, content_type, etc.)
    /// None for legacy files uploaded before E2EE
    pub encrypted_metadata: Option<Vec<u8>>,
    /// Nonce for encrypted metadata
    /// None for legacy files uploaded before E2EE
    pub encrypted_metadata_nonce: Option<Vec<u8>>,
    /// Hash of encrypted content
    /// None for legacy files uploaded before E2EE
    pub encrypted_hash: Option<String>,
}

/// Input for file insert
#[derive(Debug, Clone)]
pub struct FileInsert<'a> {
    pub doc_id: Uuid,
    pub size: i64,
    pub storage_path: &'a str,
    /// Encrypted file metadata (filename, content_type, etc.)
    pub encrypted_metadata: &'a [u8],
    /// Nonce for encrypted metadata
    pub encrypted_metadata_nonce: &'a [u8],
    /// Hash of encrypted content
    pub encrypted_hash: &'a str,
}
