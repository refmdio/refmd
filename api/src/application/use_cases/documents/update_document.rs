use uuid::Uuid;

use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::realtime_port::RealtimePort;
use crate::application::ports::storage_port::StoragePort;
use crate::domain::documents::document::Document as DomainDocument;

pub struct UpdateDocument<'a, R, S, RT>
where
    R: DocumentRepository + ?Sized,
    S: StoragePort + ?Sized,
    RT: RealtimePort + ?Sized,
{
    pub repo: &'a R,
    pub storage: &'a S,
    pub realtime: &'a RT,
}

impl<'a, R, S, RT> UpdateDocument<'a, R, S, RT>
where
    R: DocumentRepository + ?Sized,
    S: StoragePort + ?Sized,
    RT: RealtimePort + ?Sized,
{
    // parent_id: None => not provided; Some(None) => set null; Some(Some(uuid)) => set value
    pub async fn execute(
        &self,
        id: Uuid,
        user_id: Uuid,
        title: Option<String>,
        parent_id: Option<Option<Uuid>>,
    ) -> anyhow::Result<Option<DomainDocument>> {
        let row = self
            .repo
            .update_title_and_parent_for_user(id, user_id, title, parent_id)
            .await?;
        if let Some(doc) = &row {
            if doc.doc_type == "folder" {
                let _ = self.storage.move_folder_subtree(id).await;
            } else {
                let _ = self.realtime.force_save_to_fs(&id.to_string()).await;
            }
        }
        Ok(row)
    }
}
