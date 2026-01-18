use std::sync::Arc;

use uuid::Uuid;

use crate::core::services::errors::ServiceError;
use crate::documents::dtos::{
    ActiveShareItemDto, ApplicableShareDto, CreatedShareDto, ShareBrowseResponseDto,
    ShareDocumentDto, ShareItemDto, ShareMountDto,
};
use crate::documents::ports::sharing::shares_repository::{ChildShareInfo, SharesRepository};
use async_trait::async_trait;
use domain::access::permissions::PermissionSet;
use domain::documents::share;

mod browse;
mod crud;
mod guards;
mod materialize;
mod mounts;

pub struct ShareService {
    repo: Arc<dyn SharesRepository>,
}

pub struct ShareDocumentMeta {
    pub document_id: Uuid,
    pub owner_id: Uuid,
    pub workspace_id: Uuid,
}

#[async_trait]
pub trait ShareServiceFacade: Send + Sync {
    async fn create_share(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
        document_id: Uuid,
        permission: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<CreatedShareDto, ServiceError>;

    async fn list_document_shares(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        document_id: Uuid,
    ) -> Result<Vec<ShareItemDto>, ServiceError>;

    async fn delete_share(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        token: &str,
    ) -> Result<bool, ServiceError>;

    async fn list_applicable(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<Vec<ApplicableShareDto>, ServiceError>;

    async fn list_active(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<Vec<ActiveShareItemDto>, ServiceError>;

    async fn validate_token(&self, token: &str) -> Result<Option<ShareDocumentDto>, ServiceError>;

    async fn resolve_share_context(
        &self,
        token: &str,
    ) -> Result<Option<share::ShareContext>, ServiceError>;

    async fn browse_share(
        &self,
        token: &str,
    ) -> Result<Option<ShareBrowseResponseDto>, ServiceError>;

    async fn share_document_meta(
        &self,
        token: &str,
    ) -> Result<Option<ShareDocumentMeta>, ServiceError>;

    async fn save_share_mount(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
        token: &str,
        parent_folder_id: Option<Uuid>,
    ) -> Result<ShareMountDto, ServiceError>;

    async fn list_share_mounts(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<Vec<ShareMountDto>, ServiceError>;

    async fn delete_share_mount(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        mount_id: Uuid,
    ) -> Result<bool, ServiceError>;

    async fn materialize_folder_share(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
        token: &str,
    ) -> Result<i64, ServiceError>;

    /// Get child share info (token, share_id, encrypted_dek) for documents in a folder share
    async fn list_child_share_info(
        &self,
        parent_share_id: Uuid,
    ) -> Result<Vec<ChildShareInfo>, ServiceError>;
}

#[async_trait]
impl ShareServiceFacade for ShareService {
    async fn create_share(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
        document_id: Uuid,
        permission: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<CreatedShareDto, ServiceError> {
        self.create_share(
            workspace_id,
            actor_id,
            permissions,
            document_id,
            permission,
            expires_at,
        )
        .await
    }

    async fn list_document_shares(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        document_id: Uuid,
    ) -> Result<Vec<ShareItemDto>, ServiceError> {
        self.list_document_shares(workspace_id, permissions, document_id)
            .await
    }

    async fn delete_share(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        token: &str,
    ) -> Result<bool, ServiceError> {
        self.delete_share(workspace_id, permissions, token).await
    }

    async fn list_applicable(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<Vec<ApplicableShareDto>, ServiceError> {
        self.list_applicable(workspace_id, permissions, doc_id)
            .await
    }

    async fn list_active(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<Vec<ActiveShareItemDto>, ServiceError> {
        self.list_active(workspace_id, permissions).await
    }

    async fn validate_token(&self, token: &str) -> Result<Option<ShareDocumentDto>, ServiceError> {
        self.validate_token(token).await
    }

    async fn resolve_share_context(
        &self,
        token: &str,
    ) -> Result<Option<share::ShareContext>, ServiceError> {
        self.resolve_share_context(token).await
    }

    async fn browse_share(
        &self,
        token: &str,
    ) -> Result<Option<ShareBrowseResponseDto>, ServiceError> {
        self.browse_share(token).await
    }

    async fn share_document_meta(
        &self,
        token: &str,
    ) -> Result<Option<ShareDocumentMeta>, ServiceError> {
        self.share_document_meta(token).await
    }

    async fn save_share_mount(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
        token: &str,
        parent_folder_id: Option<Uuid>,
    ) -> Result<ShareMountDto, ServiceError> {
        self.save_share_mount(workspace_id, actor_id, permissions, token, parent_folder_id)
            .await
    }

    async fn list_share_mounts(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<Vec<ShareMountDto>, ServiceError> {
        self.list_share_mounts(workspace_id, permissions).await
    }

    async fn delete_share_mount(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        mount_id: Uuid,
    ) -> Result<bool, ServiceError> {
        self.delete_share_mount(workspace_id, permissions, mount_id)
            .await
    }

    async fn materialize_folder_share(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
        token: &str,
    ) -> Result<i64, ServiceError> {
        self.materialize_folder_share(workspace_id, actor_id, permissions, token)
            .await
    }

    async fn list_child_share_info(
        &self,
        parent_share_id: Uuid,
    ) -> Result<Vec<ChildShareInfo>, ServiceError> {
        self.repo
            .list_child_share_info(parent_share_id)
            .await
            .map_err(|e| ServiceError::Unexpected(e.into()))
    }
}

impl ShareService {
    pub fn new(repo: Arc<dyn SharesRepository>) -> Self {
        Self { repo }
    }
}
