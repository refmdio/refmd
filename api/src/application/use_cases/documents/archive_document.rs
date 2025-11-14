use uuid::Uuid;

use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::realtime_port::RealtimeEngine;
use crate::domain::documents::document::Document as DomainDocument;

pub struct ArchiveDocument<'a, R, RT>
where
    R: DocumentRepository + ?Sized,
    RT: RealtimeEngine + ?Sized,
{
    pub repo: &'a R,
    pub realtime: &'a RT,
}

impl<'a, R, RT> ArchiveDocument<'a, R, RT>
where
    R: DocumentRepository + ?Sized,
    RT: RealtimeEngine + ?Sized,
{
    pub async fn execute(
        &self,
        owner_id: Uuid,
        doc_id: Uuid,
    ) -> anyhow::Result<Option<DomainDocument>> {
        let meta = match self.repo.get_meta_for_owner(doc_id, owner_id).await? {
            Some(meta) => meta,
            None => return Ok(None),
        };
        if meta.archived_at.is_some() {
            return Ok(None);
        }

        let subtree = self
            .repo
            .list_owned_subtree_documents(owner_id, doc_id)
            .await?;
        for node in &subtree {
            if node.doc_type != "folder" {
                self.realtime.force_persist(&node.id.to_string()).await?;
            }
        }

        let doc = self
            .repo
            .archive_subtree(doc_id, owner_id, owner_id)
            .await?;

        if doc.is_some() {
            for node in &subtree {
                self.realtime
                    .set_document_editable(&node.id.to_string(), false)
                    .await?;
            }
        }

        Ok(doc)
    }
}
