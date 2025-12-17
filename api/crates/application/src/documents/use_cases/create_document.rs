use uuid::Uuid;

use crate::documents::ports::document_repository::{
    DocumentPathConflictError, DocumentRepository, DocumentRepositoryTx,
};
use domain::documents::path as doc_path;
use domain::documents::document::Document as DomainDocument;
use domain::documents::doc_type::DocumentType;
use domain::documents::title::Title;

const MAX_SLUG_ATTEMPTS: usize = 50;

#[async_trait::async_trait]
pub trait CreateDocumentRepository: Send {
    async fn create_for_user(
        &mut self,
        workspace_id: Uuid,
        created_by: Uuid,
        title: &Title,
        parent_id: Option<Uuid>,
        doc_type: DocumentType,
        created_by_plugin: Option<&str>,
        slug: &doc_path::Slug,
        desired_path: &doc_path::DesiredPath,
    ) -> anyhow::Result<DomainDocument>;
}

#[async_trait::async_trait]
impl<R: DocumentRepository + ?Sized> CreateDocumentRepository for &R {
    async fn create_for_user(
        &mut self,
        workspace_id: Uuid,
        created_by: Uuid,
        title: &Title,
        parent_id: Option<Uuid>,
        doc_type: DocumentType,
        created_by_plugin: Option<&str>,
        slug: &doc_path::Slug,
        desired_path: &doc_path::DesiredPath,
    ) -> anyhow::Result<DomainDocument> {
        (*self)
            .create_for_user(
                workspace_id,
                created_by,
                title,
                parent_id,
                doc_type,
                created_by_plugin,
                slug,
                desired_path,
            )
            .await
    }
}

#[async_trait::async_trait]
impl<'a> CreateDocumentRepository for (dyn DocumentRepositoryTx + 'a) {
    async fn create_for_user(
        &mut self,
        workspace_id: Uuid,
        created_by: Uuid,
        title: &Title,
        parent_id: Option<Uuid>,
        doc_type: DocumentType,
        created_by_plugin: Option<&str>,
        slug: &doc_path::Slug,
        desired_path: &doc_path::DesiredPath,
    ) -> anyhow::Result<DomainDocument> {
        DocumentRepositoryTx::create_for_user(
            self,
            workspace_id,
            created_by,
            title,
            parent_id,
            doc_type,
            created_by_plugin,
            slug,
            desired_path,
        )
        .await
    }
}

pub struct CreateDocument<'a, R: CreateDocumentRepository + ?Sized> {
    pub repo: &'a mut R,
}

impl<'a, R: CreateDocumentRepository + ?Sized> CreateDocument<'a, R> {
    pub async fn execute(
        &mut self,
        workspace_id: Uuid,
        created_by: Uuid,
        title: &Title,
        parent_id: Option<Uuid>,
        parent_desired_path: Option<&doc_path::DesiredPath>,
        doc_type: DocumentType,
        created_by_plugin: Option<&str>,
    ) -> anyhow::Result<DomainDocument> {
        let base_slug = doc_path::Slug::from_title(title.as_str());
        for (slug, desired_path) in doc_path::desired_path_candidates(
            &base_slug,
            parent_desired_path,
            doc_type,
            MAX_SLUG_ATTEMPTS,
        ) {
            let result = self
                .repo
                .create_for_user(
                    workspace_id,
                    created_by,
                    title,
                    parent_id,
                    doc_type,
                    created_by_plugin,
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
