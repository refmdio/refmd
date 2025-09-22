use uuid::Uuid;

use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::storage_port::StoragePort;

pub struct DeleteDocument<'a, R, S>
where
    R: DocumentRepository + ?Sized,
    S: StoragePort + ?Sized,
{
    pub repo: &'a R,
    pub storage: &'a S,
}

impl<'a, R, S> DeleteDocument<'a, R, S>
where
    R: DocumentRepository + ?Sized,
    S: StoragePort + ?Sized,
{
    pub async fn execute(&self, id: Uuid, user_id: Uuid) -> anyhow::Result<bool> {
        if let Some(dtype) = self.repo.delete_owned(id, user_id).await? {
            if dtype == "folder" {
                let _ = self.storage.delete_folder_physical(id).await;
            } else {
                let _ = self.storage.delete_doc_physical(id).await;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
