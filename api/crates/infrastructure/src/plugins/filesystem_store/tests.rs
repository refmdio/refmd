#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn prefers_semver_when_available() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("plugins_test");
        std::fs::create_dir_all(root.as_path()).unwrap();

        let store =
            FilesystemPluginStore::new(root.to_str().unwrap(), PluginExecutionLimits::default())
                .unwrap();

        let base = store.root().join("marp");
        std::fs::create_dir_all(base.join("1.9.0")).unwrap();
        std::fs::create_dir_all(base.join("1.10.0")).unwrap();

        let latest = store.latest_version_dir(&base).unwrap().unwrap();
        assert_eq!(latest.file_name().unwrap(), "1.10.0");
    }

    #[test]
    fn falls_back_to_lexical_for_non_semver() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("plugins_test_non_semver");
        std::fs::create_dir_all(root.as_path()).unwrap();

        let store =
            FilesystemPluginStore::new(root.to_str().unwrap(), PluginExecutionLimits::default())
                .unwrap();

        let base = store.root().join("example");
        std::fs::create_dir_all(base.join("beta")).unwrap();
        std::fs::create_dir_all(base.join("alpha")).unwrap();

        let latest = store.latest_version_dir(&base).unwrap().unwrap();
        assert_eq!(latest.file_name().unwrap(), "beta");
    }
}
