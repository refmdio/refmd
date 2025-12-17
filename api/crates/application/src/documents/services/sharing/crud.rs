use uuid::Uuid;

use domain::documents::share;
use domain::workspaces::permissions::PermissionSet;

use crate::core::services::errors::ServiceError;
use crate::documents::dtos::{
    ActiveShareItemDto, ApplicableShareDto, CreatedShareDto, ShareItemDto,
};
use crate::documents::use_cases::sharing::create_share::CreateShare;
use crate::documents::use_cases::sharing::delete_share::DeleteShare;
use crate::documents::use_cases::sharing::list_active::ListActiveShares;
use crate::documents::use_cases::sharing::list_applicable::ListApplicableShares;
use crate::documents::use_cases::sharing::list_document_shares::ListDocumentShares;

use super::ShareService;

use super::guards::{ensure_share_create_permission, ensure_share_delete_permission};

impl ShareService {
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
        let permission = share::SharePermission::from_str(permission)
            .ok_or(ServiceError::BadRequest("invalid_share_permission"))?;
        let uc = CreateShare {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_id, actor_id, document_id, permission, expires_at)
            .await
            .map(|res| CreatedShareDto {
                token: res.token,
                document_id: res.document_id,
                document_type: res.document_type.as_str().to_string(),
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
}
