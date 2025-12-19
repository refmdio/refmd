use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub const GIT_PULL_STATUS_PENDING: &str = "pending";
pub const GIT_PULL_STATUS_RESOLVING: &str = "resolving";
pub const GIT_PULL_STATUS_MERGED: &str = "merged";
pub const GIT_PULL_STATUS_STALE: &str = "stale";
pub const GIT_PULL_STATUS_ERROR: &str = "error";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitPullSessionStatus {
    Pending,
    Resolving,
    Merged,
    Stale,
    Error,
}

impl GitPullSessionStatus {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            GIT_PULL_STATUS_PENDING => Some(Self::Pending),
            GIT_PULL_STATUS_RESOLVING => Some(Self::Resolving),
            GIT_PULL_STATUS_MERGED => Some(Self::Merged),
            GIT_PULL_STATUS_STALE => Some(Self::Stale),
            GIT_PULL_STATUS_ERROR => Some(Self::Error),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => GIT_PULL_STATUS_PENDING,
            Self::Resolving => GIT_PULL_STATUS_RESOLVING,
            Self::Merged => GIT_PULL_STATUS_MERGED,
            Self::Stale => GIT_PULL_STATUS_STALE,
            Self::Error => GIT_PULL_STATUS_ERROR,
        }
    }

    pub const fn is_in_progress(self) -> bool {
        matches!(self, Self::Pending | Self::Resolving)
    }
}

impl fmt::Display for GitPullSessionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidGitPullSessionStatus;

impl fmt::Display for InvalidGitPullSessionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid git pull session status")
    }
}

impl std::error::Error for InvalidGitPullSessionStatus {}

impl FromStr for GitPullSessionStatus {
    type Err = InvalidGitPullSessionStatus;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(InvalidGitPullSessionStatus)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_formats_and_in_progress() {
        assert_eq!(
            GitPullSessionStatus::parse(" pending "),
            Some(GitPullSessionStatus::Pending)
        );
        assert_eq!(
            GitPullSessionStatus::parse("resolving"),
            Some(GitPullSessionStatus::Resolving)
        );
        assert_eq!(
            GitPullSessionStatus::parse("merged"),
            Some(GitPullSessionStatus::Merged)
        );
        assert_eq!(
            GitPullSessionStatus::parse("stale"),
            Some(GitPullSessionStatus::Stale)
        );
        assert_eq!(
            GitPullSessionStatus::parse("error"),
            Some(GitPullSessionStatus::Error)
        );
        assert_eq!(GitPullSessionStatus::parse("nope"), None);

        assert!(GitPullSessionStatus::Pending.is_in_progress());
        assert!(GitPullSessionStatus::Resolving.is_in_progress());
        assert!(!GitPullSessionStatus::Merged.is_in_progress());
        assert_eq!(
            GitPullSessionStatus::Merged.as_str(),
            GIT_PULL_STATUS_MERGED
        );
    }
}
