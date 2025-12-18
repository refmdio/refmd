use std::sync::Arc;

use uuid::Uuid;

use crate::core::services::errors::ServiceError;
use crate::documents::ports::document_repository::DocumentRepository;
use crate::plugins::dtos::ExecResult;
use crate::plugins::ports::plugin_repository::PluginRepository;
use crate::plugins::ports::plugin_runtime::PluginRuntime;
use crate::plugins::use_cases::exec_action::ExecutePluginAction;
use domain::workspaces::permissions::PermissionSet;

pub struct PluginExecutionService {
    plugin_repo: Arc<dyn PluginRepository>,
    document_repo: Arc<dyn DocumentRepository>,
    runtime: Arc<dyn PluginRuntime>,
    authorization: Arc<crate::core::services::authorization::AuthorizationService>,
}

impl PluginExecutionService {
    pub fn new(
        plugin_repo: Arc<dyn PluginRepository>,
        document_repo: Arc<dyn DocumentRepository>,
        runtime: Arc<dyn PluginRuntime>,
        authorization: Arc<crate::core::services::authorization::AuthorizationService>,
    ) -> Self {
        Self {
            plugin_repo,
            document_repo,
            runtime,
            authorization,
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
        allowed_doc_id: Option<Uuid>,
        actor: &crate::core::services::access::Actor,
    ) -> Result<Option<ExecResult>, ServiceError> {
        let uc = ExecutePluginAction {
            runtime: self.runtime.as_ref(),
            plugin_repo: self.plugin_repo.as_ref(),
            document_repo: self.document_repo.as_ref(),
            authorization: self.authorization.as_ref(),
        };
        uc.execute(
            workspace_id,
            user_id,
            permissions,
            plugin,
            action,
            payload,
            allowed_doc_id,
            actor,
        )
        .await
        .map_err(ServiceError::from)
    }
}
