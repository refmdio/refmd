use async_trait::async_trait;
use thiserror::Error;
use uuid::Uuid;

use domain::documents::doc_type::DocumentType;
use domain::documents::document::Document as DomainDocument;
pub use domain::documents::meta::DocMeta;
use domain::documents::path::{DesiredPath, Slug};
use domain::documents::title::Title;

#[derive(Debug, Error)]
pub enum DocumentRepositoryError {
    #[error("document path conflict")]
    PathConflict,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

pub type DocumentRepoResult<T> = Result<T, DocumentRepositoryError>;

impl From<DocumentRepositoryError> for crate::core::services::errors::ServiceError {
    fn from(err: DocumentRepositoryError) -> Self {
        match err {
            DocumentRepositoryError::PathConflict => Self::Conflict,
            DocumentRepositoryError::Unexpected(inner) => Self::Unexpected(inner),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DocumentListState {
    #[default]
    Active,
    Archived,
    All,
}

#[async_trait]
pub trait DocumentRepository: Send + Sync {
    async fn list_for_user(
        &self,
        workspace_id: Uuid,
        tag: Option<String>,
        state: DocumentListState,
    ) -> DocumentRepoResult<Vec<DomainDocument>>;

    async fn list_ids_for_user(&self, workspace_id: Uuid) -> DocumentRepoResult<Vec<Uuid>>;

    async fn list_workspace_documents(
        &self,
        workspace_id: Uuid,
    ) -> DocumentRepoResult<Vec<DomainDocument>>;

    async fn get_by_id(&self, id: Uuid) -> DocumentRepoResult<Option<DomainDocument>>;

    #[allow(clippy::too_many_arguments)]
    async fn create_for_user(
        &self,
        workspace_id: Uuid,
        created_by: Uuid,
        title: &Title,
        parent_id: Option<Uuid>,
        doc_type: DocumentType,
        created_by_plugin: Option<&str>,
        slug: &Slug,
        desired_path: &DesiredPath,
    ) -> DocumentRepoResult<DomainDocument>;

    // parent_id: None => not provided; Some(None) => set NULL; Some(Some(uuid)) => set to value
    #[allow(clippy::too_many_arguments)]
    async fn update_title_and_parent_for_user(
        &self,
        id: Uuid,
        workspace_id: Uuid,
        title: &Title,
        parent_id: Option<Option<Uuid>>,
        slug: &Slug,
        desired_path: &DesiredPath,
    ) -> DocumentRepoResult<Option<DomainDocument>>;

    // Returns Some(type) if deleted, None if not found/unauthorized
    async fn delete_owned(
        &self,
        id: Uuid,
        workspace_id: Uuid,
    ) -> DocumentRepoResult<Option<DocumentType>>;

    // Lightweight meta for ownership-scoped queries
    async fn get_meta_for_owner(
        &self,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> DocumentRepoResult<Option<DocMeta>>;

    async fn archive_subtree(
        &self,
        doc_id: Uuid,
        workspace_id: Uuid,
        archived_by: Uuid,
    ) -> DocumentRepoResult<Option<DomainDocument>>;

    async fn unarchive_subtree(
        &self,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> DocumentRepoResult<Option<DomainDocument>>;

    async fn list_owned_subtree_documents(
        &self,
        workspace_id: Uuid,
        root_id: Uuid,
    ) -> DocumentRepoResult<Vec<SubtreeDocument>>;

    /// Update encrypted title fields for E2EE documents
    async fn update_encrypted_title(
        &self,
        doc_id: Uuid,
        encrypted_title: Vec<u8>,
        encrypted_title_nonce: Vec<u8>,
    ) -> DocumentRepoResult<()>;
}

#[async_trait]
pub trait DocumentRepositoryTx: Send {
    #[allow(clippy::too_many_arguments)]
    async fn create_for_user(
        &mut self,
        workspace_id: Uuid,
        created_by: Uuid,
        title: &Title,
        parent_id: Option<Uuid>,
        doc_type: DocumentType,
        created_by_plugin: Option<&str>,
        slug: &Slug,
        desired_path: &DesiredPath,
    ) -> DocumentRepoResult<DomainDocument>;

    // parent_id: None => not provided; Some(None) => set NULL; Some(Some(uuid)) => set to value
    #[allow(clippy::too_many_arguments)]
    async fn update_title_and_parent_for_user(
        &mut self,
        id: Uuid,
        workspace_id: Uuid,
        title: &Title,
        parent_id: Option<Option<Uuid>>,
        slug: &Slug,
        desired_path: &DesiredPath,
    ) -> DocumentRepoResult<Option<DomainDocument>>;

    // Returns Some(type) if deleted, None if not found/unauthorized
    async fn delete_owned(
        &mut self,
        id: Uuid,
        workspace_id: Uuid,
    ) -> DocumentRepoResult<Option<DocumentType>>;

    // Lightweight meta for ownership-scoped queries
    async fn get_meta_for_owner(
        &mut self,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> DocumentRepoResult<Option<DocMeta>>;

    async fn archive_subtree(
        &mut self,
        doc_id: Uuid,
        workspace_id: Uuid,
        archived_by: Uuid,
    ) -> DocumentRepoResult<Option<DomainDocument>>;

    async fn unarchive_subtree(
        &mut self,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> DocumentRepoResult<Option<DomainDocument>>;

    async fn list_owned_subtree_documents(
        &mut self,
        workspace_id: Uuid,
        root_id: Uuid,
    ) -> DocumentRepoResult<Vec<SubtreeDocument>>;
}

#[derive(Debug, Clone)]
pub struct SubtreeDocument {
    pub id: Uuid,
    pub doc_type: DocumentType,
}
