use std::sync::Arc;

use uuid::Uuid;

use crate::application::dto::shares::{
    ActiveShareItemDto, ApplicableShareDto, CreatedShareDto, ShareBrowseResponseDto,
    ShareDocumentDto, ShareItemDto, ShareMountDto,
};
use crate::application::ports::shares_repository::SharesRepository;
use crate::application::services::errors::ServiceError;
use crate::application::use_cases::shares::browse_share::BrowseShare;
use crate::application::use_cases::shares::create_share::CreateShare;
use crate::application::use_cases::shares::delete_share::DeleteShare;
use crate::application::use_cases::shares::list_active::ListActiveShares;
use crate::application::use_cases::shares::list_applicable::ListApplicableShares;
use crate::application::use_cases::shares::list_document_shares::ListDocumentShares;
use crate::application::use_cases::shares::validate_share::ValidateShare;
use crate::domain::workspaces::permissions::{
    PERM_DOC_VIEW, PERM_SHARE_CREATE, PERM_SHARE_DELETE, PermissionSet,
};

pub struct ShareService {
    repo: Arc<dyn SharesRepository>,
}

pub struct ShareDocumentMeta {
    pub document_id: Uuid,
    pub owner_id: Uuid,
    pub workspace_id: Uuid,
}

impl ShareService {
    pub fn new(repo: Arc<dyn SharesRepository>) -> Self {
        Self { repo }
    }

    pub async fn create_share(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
        document_id: Uuid,
        permission: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<CreatedShareDto, ServiceError> {
        ensure_share_create_permission(permissions)?;
        let uc = CreateShare {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_id, actor_id, document_id, permission, expires_at)
            .await
            .map(|res| CreatedShareDto {
                token: res.token,
                document_id: res.document_id,
                document_type: res.document_type,
            })
            .map_err(ServiceError::from)
    }

    pub async fn list_document_shares(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        document_id: Uuid,
    ) -> Result<Vec<ShareItemDto>, ServiceError> {
        ensure_share_create_permission(permissions)?;
        let uc = ListDocumentShares {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_id, document_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn delete_share(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        token: &str,
    ) -> Result<bool, ServiceError> {
        ensure_share_delete_permission(permissions)?;
        let uc = DeleteShare {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_id, token)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn list_applicable(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<Vec<ApplicableShareDto>, ServiceError> {
        ensure_share_create_permission(permissions)?;
        let uc = ListApplicableShares {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_id, doc_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn validate_token(
        &self,
        token: &str,
    ) -> Result<Option<ShareDocumentDto>, ServiceError> {
        let uc = ValidateShare {
            repo: self.repo.as_ref(),
        };
        uc.execute(token).await.map_err(ServiceError::from)
    }

    pub async fn resolve_share_context(
        &self,
        token: &str,
    ) -> Result<
        Option<(
            Uuid,
            String,
            Option<chrono::DateTime<chrono::Utc>>,
            Uuid,
            String,
            Uuid,
        )>,
        ServiceError,
    > {
        self.repo
            .resolve_share_by_token(token)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn list_active(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<Vec<ActiveShareItemDto>, ServiceError> {
        ensure_share_create_permission(permissions)?;
        let uc = ListActiveShares {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_id).await.map_err(ServiceError::from)
    }

    pub async fn browse_share(
        &self,
        token: &str,
    ) -> Result<Option<ShareBrowseResponseDto>, ServiceError> {
        let uc = BrowseShare {
            repo: self.repo.as_ref(),
        };
        uc.execute(token).await.map_err(ServiceError::from)
    }

    pub async fn materialize_folder_share(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
        token: &str,
    ) -> Result<i64, ServiceError> {
        ensure_share_create_permission(permissions)?;
        self.repo
            .materialize_folder_share(workspace_id, actor_id, token)
            .await
            .map_err(|err| match err.to_string().as_str() {
                "not_found" => ServiceError::NotFound,
                "forbidden" => ServiceError::Forbidden,
                "bad_request" => ServiceError::BadRequest("invalid_share_scope"),
                _ => ServiceError::Unexpected(err),
            })
    }

    pub async fn save_share_mount(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
        token: &str,
        parent_folder_id: Option<Uuid>,
    ) -> Result<ShareMountDto, ServiceError> {
        ensure_doc_view_permission(permissions)?;
        let resolved = self
            .repo
            .resolve_share_by_token(token)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        let (
            _share_id,
            permission,
            expires_at,
            target_document_id,
            target_document_type,
            _workspace_id,
        ) = resolved;
        if let Some(exp) = expires_at {
            if exp < chrono::Utc::now() {
                return Err(ServiceError::NotFound);
            }
        }
        let target_title = self
            .repo
            .validate_share_token(token)
            .await
            .map_err(ServiceError::from)?
            .map(|(_, _, _, title)| title)
            .unwrap_or_else(|| "Shared document".to_string());
        let row = self
            .repo
            .create_share_mount(
                workspace_id,
                actor_id,
                token,
                target_document_id,
                &target_document_type,
                &target_title,
                &permission,
                parent_folder_id,
            )
            .await
            .map_err(|err| match err.to_string().as_str() {
                "invalid_parent" => ServiceError::BadRequest("invalid_parent"),
                _ => ServiceError::Unexpected(err),
            })?;
        Ok(ShareMountDto {
            id: row.id,
            token: row.token,
            target_document_id: row.target_document_id,
            target_document_type: row.target_document_type,
            target_title: row.target_title,
            permission: row.permission,
            parent_folder_id: row.parent_folder_id,
            created_at: row.created_at,
        })
    }

    pub async fn list_share_mounts(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<Vec<ShareMountDto>, ServiceError> {
        ensure_doc_view_permission(permissions)?;
        let rows = self
            .repo
            .list_share_mounts(workspace_id)
            .await
            .map_err(ServiceError::from)?;
        Ok(rows
            .into_iter()
            .map(|row| ShareMountDto {
                id: row.id,
                token: row.token,
                target_document_id: row.target_document_id,
                target_document_type: row.target_document_type,
                target_title: row.target_title,
                permission: row.permission,
                parent_folder_id: row.parent_folder_id,
                created_at: row.created_at,
            })
            .collect())
    }

    pub async fn delete_share_mount(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        mount_id: Uuid,
    ) -> Result<bool, ServiceError> {
        ensure_doc_view_permission(permissions)?;
        self.repo
            .delete_share_mount(workspace_id, mount_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn share_document_meta(
        &self,
        token: &str,
    ) -> Result<Option<ShareDocumentMeta>, ServiceError> {
        let meta = self
            .repo
            .get_share_document_meta(token)
            .await
            .map_err(ServiceError::from)?
            .map(|(document_id, owner_id, workspace_id)| ShareDocumentMeta {
                document_id,
                owner_id,
                workspace_id,
            });
        Ok(meta)
    }
}

fn ensure_share_create_permission(permissions: &PermissionSet) -> Result<(), ServiceError> {
    if permissions.allows(PERM_SHARE_CREATE) {
        Ok(())
    } else {
        Err(ServiceError::Forbidden)
    }
}

fn ensure_share_delete_permission(permissions: &PermissionSet) -> Result<(), ServiceError> {
    if permissions.allows(PERM_SHARE_DELETE) {
        Ok(())
    } else {
        Err(ServiceError::Forbidden)
    }
}

fn ensure_doc_view_permission(permissions: &PermissionSet) -> Result<(), ServiceError> {
    if permissions.allows(PERM_DOC_VIEW) {
        Ok(())
    } else {
        Err(ServiceError::Forbidden)
    }
}
