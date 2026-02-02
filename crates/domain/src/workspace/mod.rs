//! Workspace domain
//!
//! Manages workspaces, members, roles, and invitations.

pub mod invitation;
pub mod member;
pub mod permission;
pub mod repository;
pub mod role;
pub mod value_objects;
#[allow(clippy::module_inception)]
pub mod workspace;

// Re-export commonly used types
pub use invitation::WorkspaceInvitation;
pub use member::WorkspaceMember;
pub use permission::{WorkspacePermission, can_perform};
pub use repository::{
    WorkspaceInvitationRepository, WorkspaceMemberRepository, WorkspaceRepository,
    WorkspaceRolePermissionRepository, WorkspaceRoleRepository,
};
pub use role::{WorkspaceRole, WorkspaceRolePermission};
pub use value_objects::{
    BaseRole, BaseRoleError, InvitationId, Permission, RoleId, Slug, SlugError, WorkspaceId,
};
pub use workspace::Workspace;
