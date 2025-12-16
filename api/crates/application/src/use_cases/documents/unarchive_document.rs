use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::ports::document_repository::DocumentRepository;
use crate::ports::realtime_port::RealtimeEngine;
use domain::documents::document::Document as DomainDocument;

pub struct UnarchiveDocument<'a, R, RT>
where
    R: DocumentRepository + ?Sized,
    RT: RealtimeEngine + ?Sized,
{
    pub repo: &'a R,
    pub realtime: &'a RT,
}

impl<'a, R, RT> UnarchiveDocument<'a, R, RT>
where
    R: DocumentRepository + ?Sized,
    RT: RealtimeEngine + ?Sized,
{
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> anyhow::Result<Option<DomainDocument>> {
        let meta = match self.repo.get_meta_for_owner(doc_id, workspace_id).await? {
            Some(meta) => meta,
            None => return Ok(None),
        };
        if meta.archived_at.is_none() {
            return Ok(None);
        }

        let subtree = self
            .repo
            .list_owned_subtree_documents(workspace_id, doc_id)
            .await?;

        let doc = self.repo.unarchive_subtree(doc_id, workspace_id).await?;

        if doc.is_some() {
            for node in &subtree {
                self.realtime
                    .set_document_editable(&node.id.to_string(), true)
                    .await?;
            }
            for node in &subtree {
                if node.doc_type != "folder" {
                    self.realtime.force_persist(&node.id.to_string()).await?;
                }
            }
        }

        Ok(doc)
    }

    pub async fn execute_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> anyhow::Result<Option<DomainDocument>> {
        let meta = match self.repo.get_meta_for_owner(doc_id, workspace_id).await? {
            Some(meta) => meta,
            None => return Ok(None),
        };
        if meta.archived_at.is_none() {
            return Ok(None);
        }

        let subtree = self
            .repo
            .list_owned_subtree_documents(workspace_id, doc_id)
            .await?;

        let doc = self
            .repo
            .unarchive_subtree_tx(tx, doc_id, workspace_id)
            .await?;

        if doc.is_some() {
            for node in &subtree {
                self.realtime
                    .set_document_editable(&node.id.to_string(), true)
                    .await?;
            }
            for node in &subtree {
                if node.doc_type != "folder" {
                    self.realtime.force_persist(&node.id.to_string()).await?;
                }
            }
        }

        Ok(doc)
    }
}
