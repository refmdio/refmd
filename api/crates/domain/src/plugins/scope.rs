use std::fmt;

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
    pub fn from_str(value: &str) -> Option<Self> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginRecordScope {
    User,
    Doc,
}

impl PluginRecordScope {
    pub fn from_str(value: &str) -> Option<Self> {
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

pub const PLUGIN_INSTALLATION_STATUS_ENABLED: &str = "enabled";
pub const PLUGIN_INSTALLATION_STATUS_DISABLED: &str = "disabled";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginInstallationStatus {
    Enabled,
    Disabled,
}

impl PluginInstallationStatus {
    pub fn from_str(value: &str) -> Option<Self> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scopes() {
        assert_eq!(PluginScope::from_str("global"), Some(PluginScope::Global));
        assert_eq!(PluginScope::from_str(" user "), Some(PluginScope::User));
        assert_eq!(PluginScope::from_str("doc"), Some(PluginScope::Doc));
        assert_eq!(PluginScope::from_str("nope"), None);

        assert_eq!(PluginRecordScope::from_str("user"), Some(PluginRecordScope::User));
        assert_eq!(PluginRecordScope::from_str("doc"), Some(PluginRecordScope::Doc));
        assert_eq!(PluginRecordScope::from_str("global"), None);
    }

    #[test]
    fn parses_installation_status() {
        assert_eq!(
            PluginInstallationStatus::from_str("enabled"),
            Some(PluginInstallationStatus::Enabled)
        );
        assert_eq!(
            PluginInstallationStatus::from_str(" disabled "),
            Some(PluginInstallationStatus::Disabled)
        );
        assert_eq!(PluginInstallationStatus::from_str("nope"), None);
    }
}

