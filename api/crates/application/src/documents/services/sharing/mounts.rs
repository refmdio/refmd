use uuid::Uuid;

use domain::documents::share;
use domain::documents::title::Title;
use domain::workspaces::permissions::PermissionSet;

use crate::core::services::errors::ServiceError;
use crate::documents::dtos::ShareMountDto;

use super::ShareService;
use super::guards::ensure_doc_view_permission;

impl ShareService {
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
        if share::is_expired(resolved.expires_at.as_ref(), chrono::Utc::now()) {
            return Err(ServiceError::NotFound);
        }
        let target_title = self
            .repo
            .validate_share_token(token)
            .await
            .map_err(ServiceError::from)?
            .map(|doc| doc.title)
            .unwrap_or_else(|| Title::new("Shared document"));
        let row = self
            .repo
            .create_share_mount(
                workspace_id,
                actor_id,
                token,
                resolved.shared_id,
                resolved.shared_type,
                target_title,
                resolved.permission,
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
            target_document_type: row.target_document_type.as_str().to_string(),
            target_title: row.target_title.into_string(),
            permission: row.permission.as_str().to_string(),
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
                target_document_type: row.target_document_type.as_str().to_string(),
                target_title: row.target_title.into_string(),
                permission: row.permission.as_str().to_string(),
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
}
