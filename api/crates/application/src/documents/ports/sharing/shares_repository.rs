use async_trait::async_trait;
use uuid::Uuid;

use domain::documents::share::{ShareContext, SharePermission};
use domain::documents::doc_type::DocumentType;
use domain::documents::title::Title;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct ShareRow {
    pub id: Uuid,
    pub token: String,
    pub permission: SharePermission,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub parent_share_id: Option<Uuid>,
    pub document_id: Uuid,
    pub document_type: DocumentType,
    pub document_title: Title,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct ShareMountRow {
    pub id: Uuid,
    pub token: String,
    pub target_document_id: Uuid,
    pub target_document_type: DocumentType,
    pub target_title: Title,
    pub permission: SharePermission,
    pub parent_folder_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct CreatedShare {
    pub token: String,
    pub share_id: Uuid,
    pub document_type: DocumentType,
}

#[derive(Debug, Clone)]
pub struct ShareTokenValidation {
    pub document_id: Uuid,
    pub permission: SharePermission,
    pub expires_at: Option<DateTime<Utc>>,
    pub title: Title,
}

#[derive(Debug, Clone)]
pub struct ApplicableShareRow {
    pub token: String,
    pub permission: SharePermission,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct ShareDocumentMeta {
    pub document_id: Uuid,
    pub owner_id: Uuid,
    pub workspace_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct ShareSubtreeNode {
    pub id: Uuid,
    pub title: Title,
    pub document_type: DocumentType,
    pub parent_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[async_trait]
pub trait SharesRepository: Send + Sync {
    async fn create_share(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        document_id: Uuid,
        permission: SharePermission,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<CreatedShare>;

    async fn list_document_shares(
        &self,
        workspace_id: Uuid,
        document_id: Uuid,
    ) -> anyhow::Result<Vec<ShareRow>>;

    async fn delete_share(&self, workspace_id: Uuid, token: &str) -> anyhow::Result<bool>;

    async fn validate_share_token(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<ShareTokenValidation>>;

    async fn list_applicable_shares_for_doc(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> anyhow::Result<Vec<ApplicableShareRow>>;

    async fn list_active_shares(&self, workspace_id: Uuid) -> anyhow::Result<Vec<ShareRow>>;

    async fn resolve_share_by_token(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<ShareContext>>;

    async fn list_share_mounts(&self, workspace_id: Uuid) -> anyhow::Result<Vec<ShareMountRow>>;

    async fn create_share_mount(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        token: &str,
        target_document_id: Uuid,
        target_document_type: DocumentType,
        target_title: Title,
        permission: SharePermission,
        parent_folder_id: Option<Uuid>,
    ) -> anyhow::Result<ShareMountRow>;

    async fn delete_share_mount(&self, workspace_id: Uuid, mount_id: Uuid) -> anyhow::Result<bool>;

    async fn get_share_document_meta(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<ShareDocumentMeta>>;

    async fn list_subtree_nodes(
        &self,
        root_id: Uuid,
    ) -> anyhow::Result<Vec<ShareSubtreeNode>>;

    async fn list_materialized_children(&self, parent_share_id: Uuid) -> anyhow::Result<Vec<Uuid>>;

    async fn materialize_folder_share(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        token: &str,
    ) -> anyhow::Result<i64>;

    async fn revoke_subtree_shares(&self, workspace_id: Uuid, root_id: Uuid)
    -> anyhow::Result<i64>;
}
