use uuid::Uuid;

use crate::application::ports::document_repository::DocumentRepository;
use crate::domain::documents::document::Document as DomainDocument;
use sqlx::{Postgres, Transaction};

pub struct CreateDocument<'a, R: DocumentRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: DocumentRepository + ?Sized> CreateDocument<'a, R> {
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        created_by: Uuid,
        title: &str,
        parent_id: Option<Uuid>,
        doc_type: &str,
        created_by_plugin: Option<&str>,
    ) -> anyhow::Result<DomainDocument> {
        self.repo
            .create_for_user(
                workspace_id,
                created_by,
                title,
                parent_id,
                doc_type,
                created_by_plugin,
            )
            .await
    }

    pub async fn execute_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: Uuid,
        created_by: Uuid,
        title: &str,
        parent_id: Option<Uuid>,
        doc_type: &str,
        created_by_plugin: Option<&str>,
    ) -> anyhow::Result<DomainDocument> {
        self.repo
            .create_for_user_tx(
                tx,
                workspace_id,
                created_by,
                title,
                parent_id,
                doc_type,
                created_by_plugin,
            )
            .await
    }
}
