use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub const PLUGIN_SCOPE_GLOBAL: &str = "global";
pub const PLUGIN_SCOPE_USER: &str = "user";
pub const PLUGIN_SCOPE_DOC: &str = "doc";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginScope {
    Global,
    User,
    Doc,
}

impl PluginScope {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            PLUGIN_SCOPE_GLOBAL => Some(Self::Global),
            PLUGIN_SCOPE_USER => Some(Self::User),
            PLUGIN_SCOPE_DOC => Some(Self::Doc),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Global => PLUGIN_SCOPE_GLOBAL,
            Self::User => PLUGIN_SCOPE_USER,
            Self::Doc => PLUGIN_SCOPE_DOC,
        }
    }
}

impl fmt::Display for PluginScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPluginScope;

impl fmt::Display for InvalidPluginScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid plugin scope")
    }
}

impl std::error::Error for InvalidPluginScope {}

impl FromStr for PluginScope {
    type Err = InvalidPluginScope;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(InvalidPluginScope)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginRecordScope {
    User,
    Doc,
}

impl PluginRecordScope {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            PLUGIN_SCOPE_USER => Some(Self::User),
            PLUGIN_SCOPE_DOC => Some(Self::Doc),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => PLUGIN_SCOPE_USER,
            Self::Doc => PLUGIN_SCOPE_DOC,
        }
    }
}

impl fmt::Display for PluginRecordScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPluginRecordScope;

impl fmt::Display for InvalidPluginRecordScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid plugin record scope")
    }
}

impl std::error::Error for InvalidPluginRecordScope {}

impl FromStr for PluginRecordScope {
    type Err = InvalidPluginRecordScope;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(InvalidPluginRecordScope)
    }
}

pub const PLUGIN_INSTALLATION_STATUS_ENABLED: &str = "enabled";
pub const PLUGIN_INSTALLATION_STATUS_DISABLED: &str = "disabled";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginInstallationStatus {
    Enabled,
    Disabled,
}

impl PluginInstallationStatus {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            PLUGIN_INSTALLATION_STATUS_ENABLED => Some(Self::Enabled),
            PLUGIN_INSTALLATION_STATUS_DISABLED => Some(Self::Disabled),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => PLUGIN_INSTALLATION_STATUS_ENABLED,
            Self::Disabled => PLUGIN_INSTALLATION_STATUS_DISABLED,
        }
    }
}

impl fmt::Display for PluginInstallationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPluginInstallationStatus;

impl fmt::Display for InvalidPluginInstallationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid plugin installation status")
    }
}

impl std::error::Error for InvalidPluginInstallationStatus {}

impl FromStr for PluginInstallationStatus {
    type Err = InvalidPluginInstallationStatus;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(InvalidPluginInstallationStatus)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scopes() {
        assert_eq!(PluginScope::parse("global"), Some(PluginScope::Global));
        assert_eq!(PluginScope::parse(" user "), Some(PluginScope::User));
        assert_eq!(PluginScope::parse("doc"), Some(PluginScope::Doc));
        assert_eq!(PluginScope::parse("nope"), None);

        assert_eq!(
            PluginRecordScope::parse("user"),
            Some(PluginRecordScope::User)
        );
        assert_eq!(
            PluginRecordScope::parse("doc"),
            Some(PluginRecordScope::Doc)
        );
        assert_eq!(PluginRecordScope::parse("global"), None);
    }

    #[test]
    fn parses_installation_status() {
        assert_eq!(
            PluginInstallationStatus::parse("enabled"),
            Some(PluginInstallationStatus::Enabled)
        );
        assert_eq!(
            PluginInstallationStatus::parse(" disabled "),
            Some(PluginInstallationStatus::Disabled)
        );
        assert_eq!(PluginInstallationStatus::parse("nope"), None);
    }
}
