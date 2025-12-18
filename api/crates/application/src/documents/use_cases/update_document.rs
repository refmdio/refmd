use uuid::Uuid;

use crate::documents::ports::document_repository::{
    DocumentPathConflictError, DocumentRepositoryTx,
};
use domain::documents::doc_type::DocumentType;
use domain::documents::document::Document as DomainDocument;
use domain::documents::path as doc_path;
use domain::documents::title::Title;

const MAX_SLUG_ATTEMPTS: usize = 50;

pub struct UpdateDocument<'a, R>
where
    R: DocumentRepositoryTx + ?Sized,
{
    pub repo: &'a mut R,
}

impl<'a, R> UpdateDocument<'a, R>
where
    R: DocumentRepositoryTx + ?Sized,
{
    // parent_id: None => not provided; Some(None) => set null; Some(Some(uuid)) => set value
    pub async fn execute(
        &mut self,
        id: Uuid,
        workspace_id: Uuid,
        current_title: &Title,
        current_slug: &doc_path::Slug,
        current_desired_path: &doc_path::DesiredPath,
        doc_type: DocumentType,
        title: Option<&Title>,
        parent_id: Option<Option<Uuid>>,
        parent_desired_path: Option<&doc_path::DesiredPath>,
    ) -> anyhow::Result<Option<DomainDocument>> {
        let next_title = title.unwrap_or(current_title);
        let base_slug = if title.is_some() {
            doc_path::Slug::from_title(next_title.as_str())
        } else {
            current_slug.clone()
        };
        let current_parent_path = doc_path::parent_desired_path(current_desired_path);
        let parent_path = match parent_id {
            Some(Some(_)) => parent_desired_path,
            Some(None) => None,
            None => current_parent_path.as_ref(),
        };

        for (slug, desired_path) in
            doc_path::desired_path_candidates(&base_slug, parent_path, doc_type, MAX_SLUG_ATTEMPTS)
        {
            let result = self
                .repo
                .update_title_and_parent_for_user(
                    id,
                    workspace_id,
                    next_title,
                    parent_id,
                    &slug,
                    &desired_path,
                )
                .await;
            match result {
                Ok(doc) => return Ok(doc),
                Err(err) if err.downcast_ref::<DocumentPathConflictError>().is_some() => continue,
                Err(err) => return Err(err),
            }
        }
        Err(DocumentPathConflictError.into())
    }
}
