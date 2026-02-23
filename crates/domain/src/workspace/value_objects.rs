//! Workspace domain value objects

use serde::{Deserialize, Serialize};

define_id!(/// Workspace ID
pub WorkspaceId);

define_id!(/// Role ID
pub RoleId);

define_id!(/// Invitation ID
pub InvitationId);

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

impl std::fmt::Display for BaseRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
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
        if !slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
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
