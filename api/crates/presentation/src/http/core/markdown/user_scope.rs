use uuid::Uuid;

use crate::context::AppContext;
use crate::security::{request_status, token};
use application::core::services::access;
use domain::documents::share;

pub(super) async fn resolve_user_scope_from_inputs(
    ctx: &AppContext,
    bearer_token: Option<&str>,
    share_token: Option<&str>,
) -> Option<Uuid> {
    if let Some(token) = bearer_token {
        if let Some(workspace_id) = ctx.auth_service().workspace_from_token_claim(token) {
            return Some(workspace_id);
        }
        if let Ok(Some(workspace_id)) = ctx.auth_service().workspace_from_token_async(token).await {
            return Some(workspace_id);
        }
        match token::resolve_actor_from_token_str(ctx, token).await {
            Ok(access::Actor::User(uid)) => {
                if let Ok(workspaces) = ctx.workspace_service().list_for_user(uid).await {
                    if workspaces.is_empty() {
                        return None;
                    }
                    if let Some(default_ws) = workspaces.iter().find(|ws| ws.is_default) {
                        return Some(default_ws.id);
                    }
                    return Some(workspaces[0].id);
                }
            }
            Ok(access::Actor::ShareToken(t)) => {
                if let Ok(Some(ctx_share)) = ctx.share_service().resolve_share_context(&t).await {
                    if share::is_expired(ctx_share.expires_at.as_ref(), chrono::Utc::now()) {
                        return None;
                    }
                    return Some(ctx_share.workspace_id);
                }
            }
            Ok(_) => {}
            Err(token::ActorResolveError::TokenExpired) => {
                request_status::mark_token_expired();
                return None;
            }
            Err(token::ActorResolveError::Unauthorized) => {}
        }
    }
    if let Some(token) = share_token {
        // Share token: resolve its workspace for renderer so plugin manifests can be loaded.
        match token::resolve_actor_from_token_str(ctx, token).await {
            Ok(access::Actor::User(uid)) => {
                if let Ok(workspaces) = ctx.workspace_service().list_for_user(uid).await {
                    if workspaces.is_empty() {
                        return None;
                    }
                    if let Some(default_ws) = workspaces.iter().find(|ws| ws.is_default) {
                        return Some(default_ws.id);
                    }
                    return Some(workspaces[0].id);
                }
            }
            Ok(access::Actor::ShareToken(t)) => {
                if let Ok(Some(ctx_share)) = ctx.share_service().resolve_share_context(&t).await {
                    if share::is_expired(ctx_share.expires_at.as_ref(), chrono::Utc::now()) {
                        return None;
                    }
                    return Some(ctx_share.workspace_id);
                }
            }
            Ok(_) => {}
            Err(token::ActorResolveError::TokenExpired) => {
                request_status::mark_token_expired();
                return None;
            }
            Err(token::ActorResolveError::Unauthorized) => {}
        }
    }
    None
}
