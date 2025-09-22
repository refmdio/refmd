use uuid::Uuid;

use crate::application::ports::public_repository::PublicRepository;
use crate::domain::documents::document::Document;

pub struct GetPublicByOwnerAndId<'a, R: PublicRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: PublicRepository + ?Sized> GetPublicByOwnerAndId<'a, R> {
    pub async fn execute(
        &self,
        owner_name: &str,
        doc_id: Uuid,
    ) -> anyhow::Result<Option<Document>> {
        if let Some((id, title, parent_id, doc_type, created_at, updated_at, path)) = self
            .repo
            .get_public_meta_by_owner_and_id(owner_name, doc_id)
            .await?
        {
            Ok(Some(Document {
                id,
                title,
                parent_id,
                doc_type,
                created_at,
                updated_at,
                path,
            }))
        } else {
            Ok(None)
        }
    }
}
