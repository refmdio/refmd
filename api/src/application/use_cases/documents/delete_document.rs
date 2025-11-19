use uuid::Uuid;

use crate::application::ports::document_repository::DocumentRepository;
use sqlx::{Postgres, Transaction};

pub struct DeleteDocument<'a, R>
where
    R: DocumentRepository + ?Sized,
{
    pub repo: &'a R,
}

impl<'a, R> DeleteDocument<'a, R>
where
    R: DocumentRepository + ?Sized,
{
    pub async fn execute(&self, id: Uuid, workspace_id: Uuid) -> anyhow::Result<Option<String>> {
        self.repo.delete_owned(id, workspace_id).await
    }

    pub async fn execute_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<String>> {
        self.repo.delete_owned_tx(tx, id, workspace_id).await
    }
}
