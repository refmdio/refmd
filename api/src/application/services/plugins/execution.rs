use std::sync::Arc;

use uuid::Uuid;

use crate::application::dto::plugins::ExecResult;
use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::plugin_repository::PluginRepository;
use crate::application::ports::plugin_runtime::PluginRuntime;
use crate::application::services::errors::ServiceError;
use crate::application::services::workspaces::permissions::PermissionSet;
use crate::application::use_cases::plugins::exec_action::ExecutePluginAction;

pub struct PluginExecutionService {
    plugin_repo: Arc<dyn PluginRepository>,
    document_repo: Arc<dyn DocumentRepository>,
    runtime: Arc<dyn PluginRuntime>,
}

impl PluginExecutionService {
    pub fn new(
        plugin_repo: Arc<dyn PluginRepository>,
        document_repo: Arc<dyn DocumentRepository>,
        runtime: Arc<dyn PluginRuntime>,
    ) -> Self {
        Self {
            plugin_repo,
            document_repo,
            runtime,
        }
    }

    pub async fn execute_action(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        permissions: &PermissionSet,
        plugin: &str,
        action: &str,
        payload: Option<serde_json::Value>,
    ) -> Result<Option<ExecResult>, ServiceError> {
        let uc = ExecutePluginAction {
            runtime: self.runtime.as_ref(),
            plugin_repo: self.plugin_repo.as_ref(),
            document_repo: self.document_repo.as_ref(),
        };
        uc.execute(workspace_id, user_id, permissions, plugin, action, payload)
            .await
            .map_err(ServiceError::from)
    }
}
