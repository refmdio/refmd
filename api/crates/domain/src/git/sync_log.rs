use std::fmt;

use serde::{Deserialize, Serialize};

pub const GIT_SYNC_OPERATION_PUSH: &str = "push";
pub const GIT_SYNC_OPERATION_PULL: &str = "pull";
pub const GIT_SYNC_OPERATION_COMMIT: &str = "commit";
pub const GIT_SYNC_OPERATION_INIT: &str = "init";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitSyncOperation {
    Push,
    Pull,
    Commit,
    Init,
}

impl GitSyncOperation {
    pub fn from_str(value: &str) -> Option<Self> {
        match value.trim() {
            GIT_SYNC_OPERATION_PUSH => Some(Self::Push),
            GIT_SYNC_OPERATION_PULL => Some(Self::Pull),
            GIT_SYNC_OPERATION_COMMIT => Some(Self::Commit),
            GIT_SYNC_OPERATION_INIT => Some(Self::Init),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Push => GIT_SYNC_OPERATION_PUSH,
            Self::Pull => GIT_SYNC_OPERATION_PULL,
            Self::Commit => GIT_SYNC_OPERATION_COMMIT,
            Self::Init => GIT_SYNC_OPERATION_INIT,
        }
    }
}

impl fmt::Display for GitSyncOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub const GIT_SYNC_STATUS_SUCCESS: &str = "success";
pub const GIT_SYNC_STATUS_ERROR: &str = "error";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitSyncStatus {
    Success,
    Error,
}

impl GitSyncStatus {
    pub fn from_str(value: &str) -> Option<Self> {
        match value.trim() {
            GIT_SYNC_STATUS_SUCCESS => Some(Self::Success),
            GIT_SYNC_STATUS_ERROR => Some(Self::Error),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => GIT_SYNC_STATUS_SUCCESS,
            Self::Error => GIT_SYNC_STATUS_ERROR,
        }
    }
}

impl fmt::Display for GitSyncStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats() {
        assert_eq!(
            GitSyncOperation::from_str(" push "),
            Some(GitSyncOperation::Push)
        );
        assert_eq!(
            GitSyncOperation::from_str("commit"),
            Some(GitSyncOperation::Commit)
        );
        assert_eq!(GitSyncOperation::from_str("nope"), None);
        assert_eq!(GitSyncOperation::Init.as_str(), "init");
        assert_eq!(GitSyncOperation::Pull.to_string(), "pull");

        assert_eq!(
            GitSyncStatus::from_str(" success "),
            Some(GitSyncStatus::Success)
        );
        assert_eq!(GitSyncStatus::from_str("error"), Some(GitSyncStatus::Error));
        assert_eq!(GitSyncStatus::from_str("nope"), None);
        assert_eq!(GitSyncStatus::Success.as_str(), "success");
        assert_eq!(GitSyncStatus::Error.to_string(), "error");
    }
}
