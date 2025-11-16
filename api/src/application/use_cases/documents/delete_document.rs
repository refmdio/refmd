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
    pub async fn execute(&self, id: Uuid, user_id: Uuid) -> anyhow::Result<Option<String>> {
        self.repo.delete_owned(id, user_id).await
    }

    pub async fn execute_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        user_id: Uuid,
    ) -> anyhow::Result<Option<String>> {
        self.repo.delete_owned_tx(tx, id, user_id).await
    }
}
