use uuid::Uuid;

use crate::application::ports::document_repository::DocumentRepository;
use crate::domain::documents::document::Document as DomainDocument;

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
        user_id: Uuid,
        title: Option<String>,
        parent_id: Option<Option<Uuid>>,
    ) -> anyhow::Result<Option<DomainDocument>> {
        self.repo
            .update_title_and_parent_for_user(id, user_id, title, parent_id)
            .await
    }
}
