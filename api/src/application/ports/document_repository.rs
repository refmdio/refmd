use async_trait::async_trait;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::domain::documents::document::Document as DomainDocument;
use crate::domain::documents::document::{
    BacklinkInfo as DomBacklinkInfo, OutgoingLink as DomOutgoingLink, SearchHit,
};

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
        title: &str,
        parent_id: Option<Uuid>,
        doc_type: &str,
    ) -> anyhow::Result<DomainDocument>;

    async fn create_for_user_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: Uuid,
        created_by: Uuid,
        title: &str,
        parent_id: Option<Uuid>,
        doc_type: &str,
    ) -> anyhow::Result<DomainDocument>;

    // parent_id: None => not provided; Some(None) => set NULL; Some(Some(uuid)) => set to value
    async fn update_title_and_parent_for_user(
        &self,
        id: Uuid,
        workspace_id: Uuid,
        title: Option<String>,
        parent_id: Option<Option<Uuid>>,
    ) -> anyhow::Result<Option<DomainDocument>>;

    async fn update_title_and_parent_for_user_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        workspace_id: Uuid,
        title: Option<String>,
        parent_id: Option<Option<Uuid>>,
    ) -> anyhow::Result<Option<DomainDocument>>;

    // Returns Some(type) if deleted, None if not found/unauthorized
    async fn delete_owned(&self, id: Uuid, workspace_id: Uuid) -> anyhow::Result<Option<String>>;

    async fn delete_owned_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<String>>;

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

    async fn get_meta_for_owner_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<DocMeta>>;

    async fn archive_subtree(
        &self,
        doc_id: Uuid,
        workspace_id: Uuid,
        archived_by: Uuid,
    ) -> anyhow::Result<Option<DomainDocument>>;

    async fn archive_subtree_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        doc_id: Uuid,
        workspace_id: Uuid,
        archived_by: Uuid,
    ) -> anyhow::Result<Option<DomainDocument>>;

    async fn unarchive_subtree(
        &self,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<DomainDocument>>;

    async fn unarchive_subtree_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        doc_id: Uuid,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<DomainDocument>>;

    async fn list_owned_subtree_documents(
        &self,
        workspace_id: Uuid,
        root_id: Uuid,
    ) -> anyhow::Result<Vec<SubtreeDocument>>;

    async fn list_owned_subtree_documents_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
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

#[derive(Debug, Clone)]
pub struct DocMeta {
    pub workspace_id: Uuid,
    pub doc_type: String,
    pub path: Option<String>,
    pub slug: String,
    pub desired_path: String,
    pub title: String,
    pub archived_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone)]
pub struct SubtreeDocument {
    pub id: Uuid,
    pub doc_type: String,
}
