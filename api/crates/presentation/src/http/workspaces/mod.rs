mod core;
mod invitations;
mod members;
mod permissions;
mod roles;
pub mod scope;
pub mod types;

use axum::Router;
use axum::routing::{delete, get, patch, post};

use crate::context::AppContext;

pub use core::*;
pub use invitations::*;
pub use members::*;
pub use permissions::*;
pub use roles::*;
pub use types::*;

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/workspaces", get(list_workspaces).post(create_workspace))
        .route(
            "/workspaces/:id",
            get(get_workspace_detail)
                .put(update_workspace)
                .delete(delete_workspace),
        )
        .route("/workspaces/:id/leave", post(leave_workspace))
        .route("/workspaces/:id/switch", post(switch_workspace))
        .route("/workspaces/:id/members", get(list_members))
        .route(
            "/workspaces/:id/members/:user_id",
            patch(update_member_role).delete(remove_member),
        )
        .route(
            "/workspaces/:id/permissions",
            get(get_workspace_permissions),
        )
        .route("/workspaces/:id/roles", get(list_roles).post(create_role))
        .route(
            "/workspaces/:id/roles/:role_id",
            patch(update_role).delete(delete_role),
        )
        .route(
            "/workspaces/:id/invitations",
            get(list_invitations).post(create_invitation),
        )
        .route(
            "/workspaces/:id/invitations/:invitation_id",
            delete(revoke_invitation),
        )
        .route("/workspaces/:id/download", get(download_workspace_archive))
        .route(
            "/workspace-invitations/:token/accept",
            post(accept_invitation),
        )
        .with_state(ctx)
}
