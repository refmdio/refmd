use uuid::Uuid;

use domain::access::permissions::PermissionSet;

use crate::core::services::errors::ServiceError;

use super::ShareService;
use super::guards::ensure_share_create_permission;

impl ShareService {
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
                _ => ServiceError::Unexpected(err.into()),
            })
    }
}
