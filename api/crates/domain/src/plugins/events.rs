use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub const PLUGIN_EVENT_INSTALLED: &str = "installed";
pub const PLUGIN_EVENT_UNINSTALLED: &str = "uninstalled";
pub const PLUGIN_EVENT_UPDATED: &str = "updated";
pub const PLUGIN_EVENT_PUBLISH: &str = "publish";
pub const PLUGIN_EVENT_UNPUBLISH: &str = "unpublish";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginEventKind {
    Installed,
    Uninstalled,
    Updated,
    Publish,
    Unpublish,
}

impl PluginEventKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            PLUGIN_EVENT_INSTALLED => Some(Self::Installed),
            PLUGIN_EVENT_UNINSTALLED => Some(Self::Uninstalled),
            PLUGIN_EVENT_UPDATED => Some(Self::Updated),
            PLUGIN_EVENT_PUBLISH => Some(Self::Publish),
            PLUGIN_EVENT_UNPUBLISH => Some(Self::Unpublish),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Installed => PLUGIN_EVENT_INSTALLED,
            Self::Uninstalled => PLUGIN_EVENT_UNINSTALLED,
            Self::Updated => PLUGIN_EVENT_UPDATED,
            Self::Publish => PLUGIN_EVENT_PUBLISH,
            Self::Unpublish => PLUGIN_EVENT_UNPUBLISH,
        }
    }

    pub const fn affects_manifests(self) -> bool {
        true
    }
}

impl fmt::Display for PluginEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPluginEventKind;

impl fmt::Display for InvalidPluginEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid plugin event kind")
    }
}

impl std::error::Error for InvalidPluginEventKind {}

impl FromStr for PluginEventKind {
    type Err = InvalidPluginEventKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(InvalidPluginEventKind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats() {
        assert_eq!(
            PluginEventKind::parse(" installed "),
            Some(PluginEventKind::Installed)
        );
        assert_eq!(
            PluginEventKind::parse("uninstalled"),
            Some(PluginEventKind::Uninstalled)
        );
        assert_eq!(PluginEventKind::parse("nope"), None);
        assert_eq!(PluginEventKind::Publish.as_str(), "publish");
        assert_eq!(PluginEventKind::Unpublish.to_string(), "unpublish");
    }
}
