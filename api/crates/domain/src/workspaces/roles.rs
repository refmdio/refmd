use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub const WORKSPACE_ROLE_KIND_SYSTEM: &str = "system";
pub const WORKSPACE_ROLE_KIND_CUSTOM: &str = "custom";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkspaceRoleKind {
    System,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidWorkspaceRoleKind;

impl fmt::Display for InvalidWorkspaceRoleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid workspace role kind")
    }
}

impl std::error::Error for InvalidWorkspaceRoleKind {}

impl WorkspaceRoleKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            WORKSPACE_ROLE_KIND_SYSTEM => Some(Self::System),
            WORKSPACE_ROLE_KIND_CUSTOM => Some(Self::Custom),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => WORKSPACE_ROLE_KIND_SYSTEM,
            Self::Custom => WORKSPACE_ROLE_KIND_CUSTOM,
        }
    }
}

impl fmt::Display for WorkspaceRoleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for WorkspaceRoleKind {
    type Err = InvalidWorkspaceRoleKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(InvalidWorkspaceRoleKind)
    }
}

pub const WORKSPACE_SYSTEM_ROLE_OWNER: &str = "owner";
pub const WORKSPACE_SYSTEM_ROLE_ADMIN: &str = "admin";
pub const WORKSPACE_SYSTEM_ROLE_EDITOR: &str = "editor";
pub const WORKSPACE_SYSTEM_ROLE_VIEWER: &str = "viewer";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkspaceSystemRole {
    Owner,
    Admin,
    Editor,
    Viewer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidWorkspaceSystemRole;

impl fmt::Display for InvalidWorkspaceSystemRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid workspace system role")
    }
}

impl std::error::Error for InvalidWorkspaceSystemRole {}

impl WorkspaceSystemRole {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            WORKSPACE_SYSTEM_ROLE_OWNER => Some(Self::Owner),
            WORKSPACE_SYSTEM_ROLE_ADMIN => Some(Self::Admin),
            WORKSPACE_SYSTEM_ROLE_EDITOR => Some(Self::Editor),
            WORKSPACE_SYSTEM_ROLE_VIEWER => Some(Self::Viewer),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => WORKSPACE_SYSTEM_ROLE_OWNER,
            Self::Admin => WORKSPACE_SYSTEM_ROLE_ADMIN,
            Self::Editor => WORKSPACE_SYSTEM_ROLE_EDITOR,
            Self::Viewer => WORKSPACE_SYSTEM_ROLE_VIEWER,
        }
    }
}

impl fmt::Display for WorkspaceSystemRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for WorkspaceSystemRole {
    type Err = InvalidWorkspaceSystemRole;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(InvalidWorkspaceSystemRole)
    }
}

pub const WORKSPACE_BASE_ROLE_ADMIN: &str = "admin";
pub const WORKSPACE_BASE_ROLE_EDITOR: &str = "editor";
pub const WORKSPACE_BASE_ROLE_VIEWER: &str = "viewer";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkspaceBaseRole {
    Admin,
    Editor,
    Viewer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidWorkspaceBaseRole;

impl fmt::Display for InvalidWorkspaceBaseRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid workspace base role")
    }
}

impl std::error::Error for InvalidWorkspaceBaseRole {}

impl WorkspaceBaseRole {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            WORKSPACE_BASE_ROLE_ADMIN => Some(Self::Admin),
            WORKSPACE_BASE_ROLE_EDITOR => Some(Self::Editor),
            WORKSPACE_BASE_ROLE_VIEWER => Some(Self::Viewer),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => WORKSPACE_BASE_ROLE_ADMIN,
            Self::Editor => WORKSPACE_BASE_ROLE_EDITOR,
            Self::Viewer => WORKSPACE_BASE_ROLE_VIEWER,
        }
    }
}

impl fmt::Display for WorkspaceBaseRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for WorkspaceBaseRole {
    type Err = InvalidWorkspaceBaseRole;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(InvalidWorkspaceBaseRole)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_roles() {
        assert_eq!(
            WorkspaceRoleKind::parse("system"),
            Some(WorkspaceRoleKind::System)
        );
        assert_eq!(
            WorkspaceRoleKind::parse(" custom "),
            Some(WorkspaceRoleKind::Custom)
        );
        assert_eq!(WorkspaceRoleKind::parse("nope"), None);

        assert_eq!(
            WorkspaceSystemRole::parse("owner"),
            Some(WorkspaceSystemRole::Owner)
        );
        assert_eq!(
            WorkspaceSystemRole::parse(" viewer "),
            Some(WorkspaceSystemRole::Viewer)
        );
        assert_eq!(WorkspaceSystemRole::parse("nope"), None);

        assert_eq!(
            WorkspaceBaseRole::parse("admin"),
            Some(WorkspaceBaseRole::Admin)
        );
        assert_eq!(
            WorkspaceBaseRole::parse(" editor "),
            Some(WorkspaceBaseRole::Editor)
        );
        assert_eq!(WorkspaceBaseRole::parse("owner"), None);
    }
}
