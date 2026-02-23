//! Workspace domain
//!
//! Manages workspaces, members, and roles.

pub mod invitation;
pub mod member;
pub mod permission;
pub mod repository;
pub mod role;
pub mod role_permission;
pub mod value_objects;
#[allow(clippy::module_inception)]
pub mod workspace;

// Re-export commonly used types
pub use invitation::{NewInvitationParams, WorkspaceInvitation};
pub use member::WorkspaceMember;
pub use permission::{ceiling, default_grant, is_at_or_above, privilege_level};
pub use repository::{
    WorkspaceInvitationRepository, WorkspaceMemberRepository, WorkspaceRepository,
    WorkspaceRepositoryErrorClassifier, WorkspaceRolePermissionRepository,
    WorkspaceRoleRepository, WorkspaceRoleRepositoryErrorClassifier,
};
pub use role::WorkspaceRole;
pub use role_permission::WorkspaceRolePermission;
pub use value_objects::{
    BaseRole, BaseRoleError, InvitationId, Permission, RoleId, Slug, SlugError, WorkspaceId,
};
pub use workspace::Workspace;
