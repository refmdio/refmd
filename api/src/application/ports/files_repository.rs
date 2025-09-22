use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait FilesRepository: Send + Sync {
    async fn is_owner_document(&self, doc_id: Uuid, owner_id: Uuid) -> anyhow::Result<bool>;
    async fn insert_file(
        &self,
        doc_id: Uuid,
        filename: &str,
        content_type: Option<&str>,
        size: i64,
        storage_path: &str,
    ) -> anyhow::Result<Uuid>;
    async fn get_file_meta(
        &self,
        file_id: Uuid,
    ) -> anyhow::Result<Option<(String, Option<String>, Uuid)>>; // (storage_path, content_type, owner_id)
    async fn get_file_path_by_doc_and_name(
        &self,
        doc_id: Uuid,
        filename: &str,
    ) -> anyhow::Result<Option<(String, Option<String>)>>;
    async fn list_storage_paths_for_document(&self, doc_id: Uuid) -> anyhow::Result<Vec<String>>;
}
