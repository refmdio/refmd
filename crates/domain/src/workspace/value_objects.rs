//! Workspace domain value objects

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Workspace ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkspaceId(Uuid);

impl WorkspaceId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for WorkspaceId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for WorkspaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Role ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoleId(Uuid);

impl RoleId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for RoleId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RoleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Invitation ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InvitationId(Uuid);

impl InvitationId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for InvitationId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for InvitationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Base role type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BaseRole {
    Owner,
    Admin,
    Editor,
    Viewer,
}

impl BaseRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            BaseRole::Owner => "owner",
            BaseRole::Admin => "admin",
            BaseRole::Editor => "editor",
            BaseRole::Viewer => "viewer",
        }
    }
}

impl std::str::FromStr for BaseRole {
    type Err = BaseRoleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "owner" => Ok(BaseRole::Owner),
            "admin" => Ok(BaseRole::Admin),
            "editor" => Ok(BaseRole::Editor),
            "viewer" => Ok(BaseRole::Viewer),
            _ => Err(BaseRoleError::InvalidRole(s.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BaseRoleError {
    #[error("invalid base role: {0}")]
    InvalidRole(String),
}

/// Permission name
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permission(String);

impl Permission {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Workspace slug (URL-safe identifier)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Slug(String);

impl Slug {
    pub fn new(slug: impl Into<String>) -> Result<Self, SlugError> {
        let slug = slug.into();

        if slug.is_empty() {
            return Err(SlugError::Empty);
        }

        if slug.len() > 100 {
            return Err(SlugError::TooLong);
        }

        // Slug must be lowercase alphanumeric with hyphens
        if !slug.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return Err(SlugError::InvalidCharacters);
        }

        // Must not start or end with hyphen
        if slug.starts_with('-') || slug.ends_with('-') {
            return Err(SlugError::InvalidFormat);
        }

        Ok(Self(slug))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Slug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SlugError {
    #[error("slug cannot be empty")]
    Empty,
    #[error("slug is too long (max 100 characters)")]
    TooLong,
    #[error("slug contains invalid characters (must be lowercase alphanumeric or hyphen)")]
    InvalidCharacters,
    #[error("slug cannot start or end with hyphen")]
    InvalidFormat,
}
