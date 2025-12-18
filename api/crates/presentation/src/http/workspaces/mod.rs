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

pub use core::{
    create_workspace, delete_workspace, download_workspace_archive, get_workspace_detail,
    leave_workspace, list_workspaces, switch_workspace, update_workspace,
};
pub use invitations::{accept_invitation, create_invitation, list_invitations, revoke_invitation};
pub use members::{list_members, remove_member, update_member_role};
pub use permissions::get_workspace_permissions;
pub use roles::{create_role, delete_role, list_roles, update_role};
pub use types::*;

pub mod openapi {
    pub use super::core::*;
    pub use super::invitations::*;
    pub use super::members::*;
    pub use super::permissions::*;
    pub use super::roles::*;
}

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
