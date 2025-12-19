use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use domain::access::permissions::PermissionSet;
use uuid::Uuid;

use crate::context::AppContext;
use crate::http::error::ApiError;
use crate::http::workspaces::scope as workspace_scope;
use crate::security::token::{self, Bearer};

#[derive(Debug, Clone)]
pub struct AuthedUser {
    pub user_id: Uuid,
    pub bearer_token: String,
}

#[axum::async_trait]
impl FromRequestParts<AppContext> for AuthedUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppContext,
    ) -> Result<Self, Self::Rejection> {
        let bearer = Bearer::from_request_parts(parts, state).await?;
        let bearer_token = bearer.0.clone();
        let user_id = token::require_user_id(state, bearer)
            .await
            .map_err(token::map_actor_error)?;
        Ok(Self {
            user_id,
            bearer_token,
        })
    }
}

#[derive(Debug, Clone)]
pub struct WorkspaceAuth {
    pub user_id: Uuid,
    pub workspace_id: Uuid,
    pub permissions: PermissionSet,
    pub bearer_token: String,
}

impl WorkspaceAuth {
    pub fn ensure_permission(&self, permission: &str) -> Result<(), ApiError> {
        if self.permissions.allows(permission) {
            Ok(())
        } else {
            Err(ApiError::forbidden("forbidden"))
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkspaceUser {
    pub user_id: Uuid,
    pub workspace_id: Uuid,
    pub bearer_token: String,
}

#[axum::async_trait]
impl FromRequestParts<AppContext> for WorkspaceAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppContext,
    ) -> Result<Self, Self::Rejection> {
        let bearer = Bearer::from_request_parts(parts, state).await?;
        let bearer_token = bearer.0.clone();
        let user_id = token::require_user_id(state, bearer)
            .await
            .map_err(token::map_actor_error)?;
        let workspace_id = workspace_scope::resolve_active_workspace_id(
            state,
            &parts.headers,
            Some(bearer_token.as_str()),
            user_id,
        )
        .await?;
        let permissions =
            workspace_scope::resolve_workspace_permissions(state, workspace_id, user_id).await?;
        Ok(Self {
            user_id,
            workspace_id,
            permissions,
            bearer_token,
        })
    }
}

#[axum::async_trait]
impl FromRequestParts<AppContext> for WorkspaceUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppContext,
    ) -> Result<Self, Self::Rejection> {
        let bearer = Bearer::from_request_parts(parts, state).await?;
        let bearer_token = bearer.0.clone();
        let user_id = token::require_user_id(state, bearer)
            .await
            .map_err(token::map_actor_error)?;
        let workspace_id = workspace_scope::resolve_active_workspace_id(
            state,
            &parts.headers,
            Some(bearer_token.as_str()),
            user_id,
        )
        .await?;
        Ok(Self {
            user_id,
            workspace_id,
            bearer_token,
        })
    }
}
