use uuid::Uuid;

use domain::documents::path::normalize_repo_path as normalize_domain_repo_path;

const RESERVED_REPO_PATHS: &[&str] = &[".gitignore"]; // Files managed outside Document/Files repos

pub(super) fn reserved_storage_paths(workspace_id: Uuid) -> impl Iterator<Item = String> {
    RESERVED_REPO_PATHS
        .iter()
        .map(move |rel| format!("{}/{}", workspace_id, rel.trim_start_matches('/')))
}

pub(super) fn is_reserved_repo_path(repo_path: &str) -> bool {
    let trimmed = repo_path.trim_start_matches('/');
    RESERVED_REPO_PATHS
        .iter()
        .any(|reserved| trimmed == reserved.trim_start_matches('/'))
}

pub(super) fn is_attachment_repo_path(repo_path: &str) -> bool {
    repo_path.contains("/attachments/")
}

pub(super) fn normalize_repo_path(raw: &str) -> Option<String> {
    normalize_domain_repo_path(raw)
}

#[cfg(test)]
mod tests {
    use super::{is_reserved_repo_path, normalize_repo_path, reserved_storage_paths};
    use uuid::Uuid;

    #[test]
    fn reserved_paths_are_under_workspace_root() {
        let workspace = Uuid::new_v4();
        let collected: Vec<String> = reserved_storage_paths(workspace).collect();
        assert_eq!(collected, vec![format!("{}/.gitignore", workspace)]);
    }

    #[test]
    fn normalize_handles_windows_paths() {
        let user = Uuid::new_v4();
        let path = format!(r"{}\notes\foo.md", user);
        assert_eq!(
            normalize_repo_path(&path),
            Some(format!("{}/notes/foo.md", user))
        );
    }

    #[test]
    fn normalize_filters_empty() {
        assert_eq!(normalize_repo_path(""), None);
        assert_eq!(normalize_repo_path("/"), None);
    }

    #[test]
    fn normalize_rejects_traversal() {
        assert_eq!(normalize_repo_path("../secret"), None);
        assert_eq!(normalize_repo_path("foo/../bar"), None);
    }

    #[test]
    fn detects_reserved_repo_path() {
        assert!(is_reserved_repo_path(".gitignore"));
        assert!(is_reserved_repo_path("/.gitignore"));
        assert!(!is_reserved_repo_path("docs/foo.md"));
    }
}
