//! Identity domain value objects

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Email value object
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Email(String);

#[derive(Debug, Error)]
pub enum EmailError {
    #[error("invalid email format")]
    InvalidFormat,
    #[error("email is empty")]
    Empty,
}

impl Email {
    /// Create a new email with validation
    pub fn new(email: impl Into<String>) -> Result<Self, EmailError> {
        let email = email.into();

        if email.is_empty() {
            return Err(EmailError::Empty);
        }

        // Basic email validation
        if !email.contains('@') || !email.contains('.') {
            return Err(EmailError::InvalidFormat);
        }

        Ok(Self(email.to_lowercase()))
    }

    /// Get the email as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Email {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Theme preference
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    Light,
    Dark,
    #[default]
    System,
}

impl Theme {
    pub fn as_str(&self) -> &'static str {
        match self {
            Theme::Light => "light",
            Theme::Dark => "dark",
            Theme::System => "system",
        }
    }
}

impl std::str::FromStr for Theme {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "light" => Ok(Theme::Light),
            "dark" => Ok(Theme::Dark),
            "system" => Ok(Theme::System),
            _ => Err(()),
        }
    }
}

/// Locale preference
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Locale(String);

impl Default for Locale {
    fn default() -> Self {
        Self("en".to_string())
    }
}

impl Locale {
    pub fn new(locale: impl Into<String>) -> Self {
        Self(locale.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Locale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
