use std::fmt;

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
    pub fn from_str(value: &str) -> Option<Self> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_formats_and_in_progress() {
        assert_eq!(
            GitPullSessionStatus::from_str(" pending "),
            Some(GitPullSessionStatus::Pending)
        );
        assert_eq!(
            GitPullSessionStatus::from_str("resolving"),
            Some(GitPullSessionStatus::Resolving)
        );
        assert_eq!(
            GitPullSessionStatus::from_str("merged"),
            Some(GitPullSessionStatus::Merged)
        );
        assert_eq!(
            GitPullSessionStatus::from_str("stale"),
            Some(GitPullSessionStatus::Stale)
        );
        assert_eq!(
            GitPullSessionStatus::from_str("error"),
            Some(GitPullSessionStatus::Error)
        );
        assert_eq!(GitPullSessionStatus::from_str("nope"), None);

        assert!(GitPullSessionStatus::Pending.is_in_progress());
        assert!(GitPullSessionStatus::Resolving.is_in_progress());
        assert!(!GitPullSessionStatus::Merged.is_in_progress());
        assert_eq!(
            GitPullSessionStatus::Merged.as_str(),
            GIT_PULL_STATUS_MERGED
        );
    }
}
