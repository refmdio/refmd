use std::fmt;

pub const STORAGE_INGEST_BACKEND_FS_WATCHER: &str = "fs_watcher";
pub const STORAGE_INGEST_BACKEND_RECONCILE: &str = "reconcile";
pub const STORAGE_INGEST_BACKEND_CONSISTENCY: &str = "consistency";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageIngestBackend {
    FsWatcher,
    Reconcile,
    Consistency,
    Other(String),
}

impl StorageIngestBackend {
    pub fn parse(raw: &str) -> Self {
        let trimmed = raw.trim();
        match trimmed {
            STORAGE_INGEST_BACKEND_FS_WATCHER => Self::FsWatcher,
            STORAGE_INGEST_BACKEND_RECONCILE => Self::Reconcile,
            STORAGE_INGEST_BACKEND_CONSISTENCY => Self::Consistency,
            other => Self::Other(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::FsWatcher => STORAGE_INGEST_BACKEND_FS_WATCHER,
            Self::Reconcile => STORAGE_INGEST_BACKEND_RECONCILE,
            Self::Consistency => STORAGE_INGEST_BACKEND_CONSISTENCY,
            Self::Other(value) => value.as_str(),
        }
    }

    pub fn is_fs_watcher(&self) -> bool {
        matches!(self, Self::FsWatcher)
    }
}

impl fmt::Display for StorageIngestBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_and_preserves_unknown() {
        assert_eq!(
            StorageIngestBackend::parse("fs_watcher"),
            StorageIngestBackend::FsWatcher
        );
        assert_eq!(
            StorageIngestBackend::parse(" reconcile "),
            StorageIngestBackend::Reconcile
        );
        assert_eq!(
            StorageIngestBackend::parse("consistency"),
            StorageIngestBackend::Consistency
        );
        assert_eq!(
            StorageIngestBackend::parse(" custom "),
            StorageIngestBackend::Other("custom".to_string())
        );
    }
}

