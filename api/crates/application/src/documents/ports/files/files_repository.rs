use async_trait::async_trait;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct FileMeta {
    pub storage_path: String,
    pub content_type: Option<String>,
    pub workspace_id: Uuid,
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
    async fn is_workspace_document(&self, doc_id: Uuid, workspace_id: Uuid)
    -> anyhow::Result<bool>;
    async fn insert_file(
        &self,
        doc_id: Uuid,
        filename: &str,
        content_type: Option<&str>,
        size: i64,
        storage_path: &str,
        content_hash: &str,
    ) -> anyhow::Result<Uuid>;
    async fn get_file_meta(&self, file_id: Uuid) -> anyhow::Result<Option<FileMeta>>;
    async fn get_file_path_by_doc_and_name(
        &self,
        doc_id: Uuid,
        filename: &str,
    ) -> anyhow::Result<Option<FilePathMeta>>;

    async fn list_storage_paths_for_document(&self, doc_id: Uuid) -> anyhow::Result<Vec<String>>;

    async fn list_files_for_document(&self, doc_id: Uuid) -> anyhow::Result<Vec<FileRecord>>;

    async fn list_storage_paths_for_workspace(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<Vec<String>>;

    async fn find_by_storage_path(
        &self,
        storage_path: &str,
    ) -> anyhow::Result<Option<StoredFileScope>>;

    async fn update_storage_path(&self, file_id: Uuid, storage_path: &str) -> anyhow::Result<()>;

    async fn update_hash_and_size(
        &self,
        file_id: Uuid,
        size: i64,
        content_hash: &str,
    ) -> anyhow::Result<()>;

    async fn delete_by_id(&self, file_id: Uuid) -> anyhow::Result<()>;
}

#[async_trait]
pub trait FilesRepositoryTx: Send {
    async fn list_storage_paths_for_document(
        &mut self,
        doc_id: Uuid,
    ) -> anyhow::Result<Vec<String>>;
}

#[derive(Debug, Clone)]
pub struct FileRecord {
    pub id: Uuid,
    pub filename: String,
    pub content_type: Option<String>,
    pub size: i64,
    pub storage_path: String,
    pub content_hash: String,
}
