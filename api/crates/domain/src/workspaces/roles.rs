use std::fmt;

use serde::{Deserialize, Serialize};

pub const WORKSPACE_ROLE_KIND_SYSTEM: &str = "system";
pub const WORKSPACE_ROLE_KIND_CUSTOM: &str = "custom";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkspaceRoleKind {
    System,
    Custom,
}

impl WorkspaceRoleKind {
    pub fn from_str(value: &str) -> Option<Self> {
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

impl WorkspaceSystemRole {
    pub fn from_str(value: &str) -> Option<Self> {
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

impl WorkspaceBaseRole {
    pub fn from_str(value: &str) -> Option<Self> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_roles() {
        assert_eq!(
            WorkspaceRoleKind::from_str("system"),
            Some(WorkspaceRoleKind::System)
        );
        assert_eq!(
            WorkspaceRoleKind::from_str(" custom "),
            Some(WorkspaceRoleKind::Custom)
        );
        assert_eq!(WorkspaceRoleKind::from_str("nope"), None);

        assert_eq!(
            WorkspaceSystemRole::from_str("owner"),
            Some(WorkspaceSystemRole::Owner)
        );
        assert_eq!(
            WorkspaceSystemRole::from_str(" viewer "),
            Some(WorkspaceSystemRole::Viewer)
        );
        assert_eq!(WorkspaceSystemRole::from_str("nope"), None);

        assert_eq!(
            WorkspaceBaseRole::from_str("admin"),
            Some(WorkspaceBaseRole::Admin)
        );
        assert_eq!(
            WorkspaceBaseRole::from_str(" editor "),
            Some(WorkspaceBaseRole::Editor)
        );
        assert_eq!(WorkspaceBaseRole::from_str("owner"), None);
    }
}
