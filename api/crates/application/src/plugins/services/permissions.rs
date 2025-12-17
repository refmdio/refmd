use std::sync::Arc;

use uuid::Uuid;

use crate::plugins::ports::plugin_runtime::PluginRuntime;
use crate::core::services::errors::ServiceError;

pub struct PluginPermissionService {
    runtime: Arc<dyn PluginRuntime>,
}

impl PluginPermissionService {
    pub fn new(runtime: Arc<dyn PluginRuntime>) -> Self {
        Self { runtime }
    }

    pub async fn ensure(
        &self,
        workspace_id: Option<Uuid>,
        plugin_id: &str,
        permission: &str,
    ) -> Result<(), ServiceError> {
        let perms = self
            .runtime
            .permissions(workspace_id, plugin_id)
            .await
            .map_err(ServiceError::from)?;
        let Some(perms) = perms else {
            return Err(ServiceError::NotFound);
        };
        if perms.iter().any(|p| p == permission) {
            Ok(())
        } else {
            Err(ServiceError::Forbidden)
        }
    }
}
