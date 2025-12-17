use uuid::Uuid;

use crate::documents::ports::document_repository::DocumentRepository;
use domain::documents::document::Document as DomainDocument;
use sqlx::{Postgres, Transaction};

pub struct UpdateDocument<'a, R>
where
    R: DocumentRepository + ?Sized,
{
    pub repo: &'a R,
}

impl<'a, R> UpdateDocument<'a, R>
where
    R: DocumentRepository + ?Sized,
{
    // parent_id: None => not provided; Some(None) => set null; Some(Some(uuid)) => set value
    pub async fn execute(
        &self,
        id: Uuid,
        workspace_id: Uuid,
        title: Option<String>,
        parent_id: Option<Option<Uuid>>,
    ) -> anyhow::Result<Option<DomainDocument>> {
        self.repo
            .update_title_and_parent_for_user(id, workspace_id, title, parent_id)
            .await
    }

    pub async fn execute_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        workspace_id: Uuid,
        title: Option<String>,
        parent_id: Option<Option<Uuid>>,
    ) -> anyhow::Result<Option<DomainDocument>> {
        self.repo
            .update_title_and_parent_for_user_tx(tx, id, workspace_id, title, parent_id)
            .await
    }
}
