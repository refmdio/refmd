use std::sync::Arc;

use serde_json::Value;
use uuid::Uuid;

use crate::core::services::errors::ServiceError;
use crate::identity::dtos::UserShortcutProfileDto;
use crate::identity::ports::user_shortcuts::user_shortcut_repository::UserShortcutRepository;
use crate::identity::use_cases::user_shortcuts::get_shortcuts::GetUserShortcuts;
use crate::identity::use_cases::user_shortcuts::update_shortcuts::{
    UpdateUserShortcuts, UpdateUserShortcutsError, UpdateUserShortcutsPayload,
};
use domain::identity::policy;
use domain::workspaces::permissions::PermissionSet;

pub struct UserShortcutService {
    repo: Arc<dyn UserShortcutRepository>,
    max_payload_bytes: usize,
}

impl UserShortcutService {
    pub fn new(repo: Arc<dyn UserShortcutRepository>, max_payload_bytes: usize) -> Self {
        Self {
            repo,
            max_payload_bytes,
        }
    }

    pub async fn get_profile(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<Option<UserShortcutProfileDto>, ServiceError> {
        ensure_shortcut_permission(workspace_id, permissions)?;
        let uc = GetUserShortcuts {
            repo: self.repo.as_ref(),
        };
        uc.execute(user_id).await.map_err(ServiceError::from)
    }

    pub async fn update_profile(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        permissions: &PermissionSet,
        bindings: Value,
        leader_key: Option<String>,
    ) -> Result<UserShortcutProfileDto, ServiceError> {
        ensure_shortcut_permission(workspace_id, permissions)?;
        let uc = UpdateUserShortcuts {
            repo: self.repo.as_ref(),
            max_payload_bytes: self.max_payload_bytes,
        };
        uc.execute(
            user_id,
            UpdateUserShortcutsPayload {
                bindings,
                leader_key,
            },
        )
        .await
        .map_err(|err| match err {
            UpdateUserShortcutsError::Validation(_) => {
                ServiceError::BadRequest("invalid_shortcuts_payload")
            }
            UpdateUserShortcutsError::Storage(inner) => ServiceError::Unexpected(inner),
        })
    }
}

fn ensure_shortcut_permission(
    _workspace_id: Uuid,
    permissions: &PermissionSet,
) -> Result<(), ServiceError> {
    policy::ensure_shortcut_update_allowed(permissions).map_err(|_| ServiceError::Forbidden)
}
