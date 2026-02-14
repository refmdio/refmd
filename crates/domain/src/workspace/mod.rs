//! Workspace domain
//!
//! Manages workspaces, members, and roles.

pub mod member;
pub mod permission;
pub mod repository;
pub mod role;
pub mod value_objects;
#[allow(clippy::module_inception)]
pub mod workspace;

// Re-export commonly used types
pub use member::WorkspaceMember;
pub use permission::{WorkspacePermission, can_perform};
pub use repository::{
    WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRoleRepository,
};
pub use role::WorkspaceRole;
pub use value_objects::{
    BaseRole, BaseRoleError, Permission, RoleId, Slug, SlugError, WorkspaceId,
};
pub use workspace::Workspace;
