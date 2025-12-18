use async_trait::async_trait;
use uuid::Uuid;

use domain::documents::doc_type::DocumentType;
use domain::documents::document::Document as DomainDocument;
use domain::documents::document::{
    BacklinkInfo as DomBacklinkInfo, OutgoingLink as DomOutgoingLink, SearchHit,
};
pub use domain::documents::meta::DocMeta;
use domain::documents::path::{DesiredPath, Slug};
use domain::documents::title::Title;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocumentPathConflictError;

impl std::fmt::Display for DocumentPathConflictError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "document path conflict")
    }
}

impl std::error::Error for DocumentPathConflictError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentListState {
    Active,
    Archived,
    All,
}

impl Default for DocumentListState {
    fn default() -> Self {
        DocumentListState::Active
    }
}

#[async_trait]
pub trait DocumentRepository: Send + Sync {
    async fn list_for_user(
        &self,
        workspace_id: Uuid,
        query: Option<String>,
        tag: Option<String>,
        state: DocumentListState,
    ) -> anyhow::Result<Vec<DomainDocument>>;

    async fn list_ids_for_user(&self, workspace_id: Uuid) -> anyhow::Result<Vec<Uuid>>;

    async fn list_paths_for_user(&self, workspace_id: Uuid) -> anyhow::Result<Vec<String>>;

    async fn list_workspace_documents(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<Vec<DomainDocument>>;

    async fn get_by_id(&self, id: Uuid) -> anyhow::Result<Option<DomainDocument>>;

    async fn search_for_user(
        &self,
        workspace_id: Uuid,
        query: Option<String>,
        limit: i64,
    ) -> anyhow::Result<Vec<SearchHit>>;

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
    ) -> anyhow::Result<DomainDocument>;

    // parent_id: None => not provided; Some(None) => set NULL; Some(Some(uuid)) => set to value
    async fn update_title_and_parent_for_user(
        &self,
        id: Uuid,
        workspace_id: Uuid,
        title: &Title,
        parent_id: Option<Option<Uuid>>,
        slug: &Slug,
        desired_path: &DesiredPath,
    ) -> anyhow::Result<Option<DomainDocument>>;

    // Returns Some(type) if deleted, None if not found/unauthorized
    async fn delete_owned(
        &self,
        id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<DocumentType>>;

    async fn backlinks_for(
        &self,
        workspace_id: Uuid,
        target_id: Uuid,
    ) -> anyhow::Result<Vec<DomBacklinkInfo>>;

    async fn outgoing_links_for(
        &self,
        workspace_id: Uuid,
        source_id: Uuid,
    ) -> anyhow::Result<Vec<DomOutgoingLink>>;

    // Lightweight meta for ownership-scoped queries
    async fn get_meta_for_owner(
        &self,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<DocMeta>>;

    async fn archive_subtree(
        &self,
        doc_id: Uuid,
        workspace_id: Uuid,
        archived_by: Uuid,
    ) -> anyhow::Result<Option<DomainDocument>>;

    async fn unarchive_subtree(
        &self,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<DomainDocument>>;

    async fn list_owned_subtree_documents(
        &self,
        workspace_id: Uuid,
        root_id: Uuid,
    ) -> anyhow::Result<Vec<SubtreeDocument>>;

    async fn get_by_owner_and_path(
        &self,
        workspace_id: Uuid,
        relative_path: &str,
    ) -> anyhow::Result<Option<DomainDocument>>;

    async fn update_repo_path(
        &self,
        doc_id: Uuid,
        workspace_id: Uuid,
        relative_path: &str,
    ) -> anyhow::Result<()>;
}

#[async_trait]
pub trait DocumentRepositoryTx: Send {
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
    ) -> anyhow::Result<DomainDocument>;

    // parent_id: None => not provided; Some(None) => set NULL; Some(Some(uuid)) => set to value
    async fn update_title_and_parent_for_user(
        &mut self,
        id: Uuid,
        workspace_id: Uuid,
        title: &Title,
        parent_id: Option<Option<Uuid>>,
        slug: &Slug,
        desired_path: &DesiredPath,
    ) -> anyhow::Result<Option<DomainDocument>>;

    // Returns Some(type) if deleted, None if not found/unauthorized
    async fn delete_owned(
        &mut self,
        id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<DocumentType>>;

    // Lightweight meta for ownership-scoped queries
    async fn get_meta_for_owner(
        &mut self,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<DocMeta>>;

    async fn archive_subtree(
        &mut self,
        doc_id: Uuid,
        workspace_id: Uuid,
        archived_by: Uuid,
    ) -> anyhow::Result<Option<DomainDocument>>;

    async fn unarchive_subtree(
        &mut self,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<DomainDocument>>;

    async fn list_owned_subtree_documents(
        &mut self,
        workspace_id: Uuid,
        root_id: Uuid,
    ) -> anyhow::Result<Vec<SubtreeDocument>>;
}

#[derive(Debug, Clone)]
pub struct SubtreeDocument {
    pub id: Uuid,
    pub doc_type: DocumentType,
}
