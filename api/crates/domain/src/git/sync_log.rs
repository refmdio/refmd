use std::fmt;
use std::str::FromStr;

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
    pub fn parse(value: &str) -> Option<Self> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidGitSyncOperation;

impl fmt::Display for InvalidGitSyncOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid git sync operation")
    }
}

impl std::error::Error for InvalidGitSyncOperation {}

impl FromStr for GitSyncOperation {
    type Err = InvalidGitSyncOperation;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(InvalidGitSyncOperation)
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
    pub fn parse(value: &str) -> Option<Self> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidGitSyncStatus;

impl fmt::Display for InvalidGitSyncStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid git sync status")
    }
}

impl std::error::Error for InvalidGitSyncStatus {}

impl FromStr for GitSyncStatus {
    type Err = InvalidGitSyncStatus;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(InvalidGitSyncStatus)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats() {
        assert_eq!(
            GitSyncOperation::parse(" push "),
            Some(GitSyncOperation::Push)
        );
        assert_eq!(
            GitSyncOperation::parse("commit"),
            Some(GitSyncOperation::Commit)
        );
        assert_eq!(GitSyncOperation::parse("nope"), None);
        assert_eq!(GitSyncOperation::Init.as_str(), "init");
        assert_eq!(GitSyncOperation::Pull.to_string(), "pull");

        assert_eq!(
            GitSyncStatus::parse(" success "),
            Some(GitSyncStatus::Success)
        );
        assert_eq!(GitSyncStatus::parse("error"), Some(GitSyncStatus::Error));
        assert_eq!(GitSyncStatus::parse("nope"), None);
        assert_eq!(GitSyncStatus::Success.as_str(), "success");
        assert_eq!(GitSyncStatus::Error.to_string(), "error");
    }
}
