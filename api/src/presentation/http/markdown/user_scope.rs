use uuid::Uuid;

use crate::application::access;
use crate::presentation::context::AppContext;
use crate::presentation::http::auth;

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
        if let Ok(sub) = auth::validate_bearer_str(ctx, token).await {
            if let Ok(uid) = Uuid::parse_str(&sub) {
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
        }
    }
    if let Some(token) = share_token {
        // Share token: resolve its workspace for renderer so plugin manifests can be loaded.
        if let Some(actor) = auth::resolve_actor_from_token_str(ctx, token).await {
            match actor {
                access::Actor::User(uid) => {
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
                access::Actor::ShareToken(t) => {
                    if let Ok(Some((_share_id, _perm, exp, _doc_id, _typ, workspace_id))) =
                        ctx.share_service().resolve_share_context(&t).await
                    {
                        if exp.map(|e| e < chrono::Utc::now()).unwrap_or(false) {
                            return None;
                        }
                        return Some(workspace_id);
                    }
                }
                _ => {}
            }
        }
    }
    None
}
