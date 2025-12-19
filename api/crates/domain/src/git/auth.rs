use std::fmt;
use std::str::FromStr;

pub const GIT_AUTH_TYPE_TOKEN: &str = "token";
pub const GIT_AUTH_TYPE_SSH: &str = "ssh";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitAuthType {
    Token,
    Ssh,
}

impl GitAuthType {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            GIT_AUTH_TYPE_TOKEN => Some(Self::Token),
            GIT_AUTH_TYPE_SSH => Some(Self::Ssh),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Token => GIT_AUTH_TYPE_TOKEN,
            Self::Ssh => GIT_AUTH_TYPE_SSH,
        }
    }

    pub fn validate_repository_url(self, repository_url: &str) -> bool {
        match self {
            Self::Token => repository_url.starts_with("https://"),
            Self::Ssh => true,
        }
    }
}

impl fmt::Display for GitAuthType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidGitAuthType;

impl fmt::Display for InvalidGitAuthType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid git auth type")
    }
}

impl std::error::Error for InvalidGitAuthType {}

impl FromStr for GitAuthType {
    type Err = InvalidGitAuthType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(InvalidGitAuthType)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats() {
        assert_eq!(GitAuthType::parse(" token "), Some(GitAuthType::Token));
        assert_eq!(GitAuthType::parse("ssh"), Some(GitAuthType::Ssh));
        assert_eq!(GitAuthType::parse("nope"), None);
        assert_eq!(GitAuthType::Token.as_str(), GIT_AUTH_TYPE_TOKEN);
        assert_eq!(GitAuthType::Ssh.to_string(), GIT_AUTH_TYPE_SSH);
    }

    #[test]
    fn token_requires_https_url() {
        assert!(GitAuthType::Token.validate_repository_url("https://example.com/repo.git"));
        assert!(!GitAuthType::Token.validate_repository_url("http://example.com/repo.git"));
        assert!(GitAuthType::Ssh.validate_repository_url("ssh://example.com/repo.git"));
        assert!(GitAuthType::Ssh.validate_repository_url("git@example.com:repo.git"));
    }
}
