use axum::http::HeaderMap;
use uuid::Uuid;

use crate::context::{HasAuthServices, HasShareService, HasWorkspaceService};
use crate::http::error::ApiError;
use crate::http::workspaces::scope as workspace_scope;
use crate::security::token;
use application::core::services::access;
use application::core::services::errors::ServiceError;
use application::plugins::services::management;
use domain::access::permissions::{PERM_DOC_EDIT, PERM_DOC_VIEW, PERM_PLUGIN_RUN, PermissionSet};
use domain::documents::share;

pub const PERMISSION_DOC_READ: &str = "doc.read";
pub const PERMISSION_DOC_WRITE: &str = "doc.write";

#[derive(Clone)]
pub struct PluginUserContext {
    pub workspace_id: Uuid,
    pub user_id: Uuid,
    pub permissions: PermissionSet,
    pub actor: access::Actor,
}

pub async fn resolve_plugin_user_context(
    ctx: &(impl HasAuthServices + HasWorkspaceService + HasShareService),
    headers: &HeaderMap,
    bearer_token: &str,
    required_permission: Option<&str>,
) -> Result<PluginUserContext, ApiError> {
    let actor = token::resolve_actor_from_token_str(ctx, bearer_token)
        .await
        .map_err(token::map_actor_error)?;

    match actor {
        access::Actor::User(user_id) => {
            let workspace_id = workspace_scope::resolve_active_workspace_id(
                ctx,
                headers,
                Some(bearer_token),
                user_id,
            )
            .await?;
            let permissions =
                workspace_scope::resolve_workspace_permissions(ctx, workspace_id, user_id).await?;
            if let Some(permission) = required_permission
                && !permissions.allows(permission)
            {
                return Err(ApiError::forbidden("forbidden"));
            }
            Ok(PluginUserContext {
                workspace_id,
                user_id,
                permissions,
                actor: access::Actor::User(user_id),
            })
        }
        access::Actor::ShareToken(token) => {
            let ctx_share = ctx
                .share_service()
                .resolve_share_context(&token)
                .await
                .map_err(|err| crate::http::error::map_service_error(err, "share_service_error"))?
                .ok_or(ApiError::unauthorized("unauthorized"))?;
            if share::is_expired(ctx_share.expires_at.as_ref(), chrono::Utc::now()) {
                return Err(ApiError::unauthorized("share_expired"));
            }
            let mut permissions = PermissionSet::from_slice(&[PERM_PLUGIN_RUN, PERM_DOC_VIEW]);
            if ctx_share.permission.allows_edit() {
                permissions.insert(PERM_DOC_EDIT);
            }
            if let Some(permission) = required_permission
                && !permissions.allows(permission)
            {
                return Err(ApiError::forbidden("forbidden"));
            }
            Ok(PluginUserContext {
                workspace_id: ctx_share.workspace_id,
                // Share tokens do not map to a user; use workspace_id as a stable placeholder
                user_id: ctx_share.workspace_id,
                permissions,
                actor: access::Actor::ShareToken(token),
            })
        }
        _ => Err(ApiError::unauthorized("unauthorized")),
    }
}

pub fn ensure_valid_plugin_id(id: &str) -> Result<(), ApiError> {
    management::validate_plugin_id(id).map_err(map_plugin_service_error)
}

pub fn map_plugin_service_error(err: ServiceError) -> crate::http::error::ApiError {
    crate::http::error::map_service_error_no_log(err)
}
