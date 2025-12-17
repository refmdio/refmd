use axum::http::HeaderMap;
use axum::http::StatusCode;
use uuid::Uuid;

use application::core::services::access;
use application::core::services::errors::ServiceError;
use application::plugins::services::management;
use domain::documents::share;
use domain::workspaces::permissions::{
    PERM_DOC_EDIT, PERM_DOC_VIEW, PERM_PLUGIN_RUN, PermissionSet,
};
use crate::context::AppContext;
use crate::http::workspaces::scope as workspace_scope;
use crate::security::{request_status, token};

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
    ctx: &AppContext,
    headers: &HeaderMap,
    bearer_token: &str,
    required_permission: Option<&str>,
) -> Result<PluginUserContext, StatusCode> {
    let actor = match token::resolve_actor_from_token_str(ctx, bearer_token).await {
        Ok(actor) => actor,
        Err(token::ActorResolveError::TokenExpired) => {
            request_status::mark_token_expired();
            return Err(StatusCode::UNAUTHORIZED);
        }
        Err(token::ActorResolveError::Unauthorized) => return Err(StatusCode::UNAUTHORIZED),
    };

    match actor {
        access::Actor::User(user_id) => {
            let workspace_id =
                workspace_scope::resolve_active_workspace_id(ctx, headers, Some(bearer_token), user_id)
                    .await
                    .map_err(|_| StatusCode::FORBIDDEN)?;
            let permissions = workspace_scope::resolve_workspace_permissions(ctx, workspace_id, user_id)
                .await
                .map_err(|_| StatusCode::FORBIDDEN)?;
            if let Some(permission) = required_permission {
                if !permissions.allows(permission) {
                    return Err(StatusCode::FORBIDDEN);
                }
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
                .map_err(|_| StatusCode::UNAUTHORIZED)?
                .ok_or(StatusCode::UNAUTHORIZED)?;
            if share::is_expired(ctx_share.expires_at.as_ref(), chrono::Utc::now()) {
                return Err(StatusCode::UNAUTHORIZED);
            }
            let mut permissions = PermissionSet::from_slice(&[PERM_PLUGIN_RUN, PERM_DOC_VIEW]);
            if ctx_share.permission.allows_edit() {
                permissions.insert(PERM_DOC_EDIT);
            }
            if let Some(permission) = required_permission {
                if !permissions.allows(permission) {
                    return Err(StatusCode::FORBIDDEN);
                }
            }
            Ok(PluginUserContext {
                workspace_id: ctx_share.workspace_id,
                // Share tokens do not map to a user; use workspace_id as a stable placeholder
                user_id: ctx_share.workspace_id,
                permissions,
                actor: access::Actor::ShareToken(token),
            })
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

pub fn ensure_valid_plugin_id(id: &str) -> Result<(), StatusCode> {
    management::validate_plugin_id(id).map_err(map_plugin_service_error)
}

pub fn map_plugin_service_error(err: ServiceError) -> StatusCode {
    match err {
        ServiceError::Unauthorized | ServiceError::TokenExpired => StatusCode::UNAUTHORIZED,
        ServiceError::Forbidden => StatusCode::FORBIDDEN,
        ServiceError::Conflict => StatusCode::CONFLICT,
        ServiceError::NotFound => StatusCode::NOT_FOUND,
        ServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
        ServiceError::Unexpected(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
