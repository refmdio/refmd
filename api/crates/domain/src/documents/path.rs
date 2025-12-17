use anyhow::{anyhow, bail};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

use crate::documents::doc_type::DocumentType;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RepoPath(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidRepoPath;

impl fmt::Display for InvalidRepoPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid repo path")
    }
}

impl std::error::Error for InvalidRepoPath {}

impl RepoPath {
    pub fn new(raw: impl Into<String>) -> Result<Self, InvalidRepoPath> {
        let raw = raw.into();
        let normalized = normalize_repo_path_impl(&raw).ok_or(InvalidRepoPath)?;
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for RepoPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Slug(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidSlug;

impl fmt::Display for InvalidSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid slug")
    }
}

impl std::error::Error for InvalidSlug {}

impl Slug {
    pub fn from_title(title: &str) -> Self {
        Self(slugify_impl(title))
    }

    pub fn new(raw: impl Into<String>) -> Result<Self, InvalidSlug> {
        let raw = raw.into();
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(InvalidSlug);
        }
        Ok(Self(trimmed.to_string()))
    }

    pub fn with_suffix(&self, attempt: usize) -> Self {
        Self(apply_slug_suffix(self.as_str(), attempt))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for Slug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DesiredPath(String);

impl DesiredPath {
    pub fn root() -> Self {
        Self(String::new())
    }

    pub fn new(raw: impl Into<String>) -> Self {
        let raw = raw.into();
        Self(raw.trim_start_matches('/').replace('\\', "/"))
    }

    pub fn from_parent_and_slug(
        parent_desired_path: Option<&DesiredPath>,
        slug: &Slug,
        doc_type: DocumentType,
    ) -> Self {
        let prefix = parent_desired_path
            .map(|p| p.as_str())
            .filter(|p| !p.is_empty())
            .map(|p| {
                if p.ends_with('/') {
                    p.to_string()
                } else {
                    format!("{p}/")
                }
            })
            .unwrap_or_default();

        let desired = if doc_type.is_folder() {
            format!("{prefix}{}", slug.as_str())
        } else {
            format!("{prefix}{}.md", slug.as_str())
        };
        Self::new(desired)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for DesiredPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Convert an absolute storage path (/workspace_id/... or workspace_id/...) to a repo-relative path.
pub fn repo_relative_from_storage(workspace_id: Uuid, storage_path: &str) -> Option<RepoPath> {
    let trimmed = storage_path.trim_start_matches('/');
    let owner_prefix = workspace_id.to_string();
    let remainder = trimmed
        .strip_prefix(&owner_prefix)
        .map(|rest| rest.trim_start_matches('/'))
        .unwrap_or(trimmed);
    if remainder.is_empty() {
        None
    } else {
        RepoPath::new(remainder.to_string()).ok()
    }
}

/// Normalize a repo-relative path string.
///
/// - Trims whitespace and leading slashes
/// - Rejects traversal (`..`) and absolute paths
/// - Collapses redundant separators and `.` segments
/// - Standardizes path separators to `/`
pub fn normalize_repo_path(repo_path: &str) -> Option<String> {
    normalize_repo_path_impl(repo_path)
}

/// Convert a stored doc path (which may be absolute or prefixed with workspace id) to repo-relative.
pub fn workspace_repo_relative(
    workspace_id: Uuid,
    stored_path: Option<&str>,
) -> Option<RepoPath> {
    let stored = stored_path?.trim_start_matches('/');
    if stored.is_empty() {
        return None;
    }
    let owner_prefix = workspace_id.to_string();
    let repo = if let Some(rest) = stored.strip_prefix(&owner_prefix) {
        rest.trim_start_matches('/')
    } else {
        stored
    };
    if repo.is_empty() {
        None
    } else {
        RepoPath::new(repo.to_string()).ok()
    }
}

fn slugify_impl(title: &str) -> String {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        return "untitled".to_string();
    }

    let mut slug = String::with_capacity(trimmed.len());
    let mut last_was_space = false;
    for ch in trimmed.chars() {
        if ch.is_control() {
            continue;
        }
        if ch.is_whitespace() {
            if !last_was_space {
                slug.push(' ');
                last_was_space = true;
            }
            continue;
        }
        last_was_space = false;
        let safe = match ch {
            '/' | '\\' | ':' | '*' | '?' | '\"' | '<' | '>' | '|' => '-',
            _ => ch,
        };
        slug.push(safe);
    }

    let mut slug = slug
        .trim_matches(|c: char| matches!(c, ' ' | '-'))
        .to_string();
    if slug.is_empty() {
        slug.push_str("untitled");
    }
    if slug.len() > 100 {
        slug.truncate(100);
    }
    slug
}

pub fn apply_slug_suffix(base: &str, attempt: usize) -> String {
    if attempt == 0 {
        base.to_string()
    } else {
        format!("{base}-{}", attempt + 1)
    }
}

pub fn desired_path_candidates<'a>(
    base_slug: &'a Slug,
    parent_desired_path: Option<&'a DesiredPath>,
    doc_type: DocumentType,
    max_attempts: usize,
) -> impl Iterator<Item = (Slug, DesiredPath)> + 'a {
    (0..max_attempts).map(move |attempt| {
        let slug = base_slug.with_suffix(attempt);
        let desired_path = DesiredPath::from_parent_and_slug(parent_desired_path, &slug, doc_type);
        (slug, desired_path)
    })
}

pub fn parent_desired_path(desired_path: &DesiredPath) -> Option<DesiredPath> {
    let mut parts = desired_path.as_str().rsplitn(2, '/');
    parts.next()?; // skip current file/folder
    parts.next().map(DesiredPath::new)
}

pub fn slug_from_desired_path(desired_path: &DesiredPath) -> anyhow::Result<Slug> {
    let segment = desired_path
        .as_str()
        .rsplit('/')
        .next()
        .ok_or_else(|| anyhow!("invalid_desired_path"))?;
    let trimmed = segment.trim();
    if trimmed.is_empty() {
        bail!("invalid_desired_path_segment");
    }
    let slug = trimmed
        .strip_suffix(".md")
        .unwrap_or(trimmed)
        .trim_matches('/');
    if slug.is_empty() {
        bail!("invalid_slug_from_path");
    }
    Slug::new(slug.to_string()).map_err(|_| anyhow!("invalid_slug_from_path"))
}

fn normalize_repo_path_impl(repo_path: &str) -> Option<String> {
    let trimmed = repo_path.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let mut normalized = PathBuf::new();
    for component in Path::new(trimmed).components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => continue,
            _ => return None,
        }
    }
    if normalized.as_os_str().is_empty() {
        return None;
    }
    Some(normalized.to_string_lossy().replace('\\', "/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::documents::doc_type::DocumentType;

    #[test]
    fn repo_path_new_normalizes_and_rejects_traversal() {
        assert_eq!(RepoPath::new("//docs//foo.md").unwrap().as_str(), "docs/foo.md");
        assert!(RepoPath::new("../secret").is_err());
        assert!(RepoPath::new("foo/../bar").is_err());
    }

    #[test]
    fn slug_new_rejects_empty() {
        assert!(Slug::new("".to_string()).is_err());
        assert!(Slug::new("   ".to_string()).is_err());
    }

    #[test]
    fn repo_relative_strips_workspace_prefix() {
        let ws = Uuid::new_v4();
        let p = format!("{}/foo/bar.md", ws);
        assert_eq!(
            repo_relative_from_storage(ws, &p),
            Some(RepoPath::new("foo/bar.md".to_string()).unwrap())
        );
        let with_slash = format!("/{}/foo/bar.md", ws);
        assert_eq!(
            repo_relative_from_storage(ws, &with_slash),
            Some(RepoPath::new("foo/bar.md".to_string()).unwrap())
        );
    }

    #[test]
    fn repo_relative_keeps_plain_paths() {
        let ws = Uuid::new_v4();
        assert_eq!(
            repo_relative_from_storage(ws, "foo/bar.md"),
            Some(RepoPath::new("foo/bar.md".to_string()).unwrap())
        );
    }

    #[test]
    fn repo_relative_empty_becomes_none() {
        let ws = Uuid::new_v4();
        assert_eq!(repo_relative_from_storage(ws, "/"), None);
        let p = format!("{}/", ws);
        assert_eq!(repo_relative_from_storage(ws, &p), None);
    }

    #[test]
    fn workspace_repo_relative_strips_workspace_prefix_and_slash() {
        let ws = Uuid::new_v4();
        let p = format!("{}/docs/readme.md", ws);
        assert_eq!(
            workspace_repo_relative(ws, Some(&p)),
            Some(RepoPath::new("docs/readme.md".to_string()).unwrap())
        );
        let with_slash = format!("/{}/docs/readme.md", ws);
        assert_eq!(
            workspace_repo_relative(ws, Some(&with_slash)),
            Some(RepoPath::new("docs/readme.md".to_string()).unwrap())
        );
    }

    #[test]
    fn workspace_repo_relative_passes_through_repo_paths() {
        let ws = Uuid::new_v4();
        assert_eq!(
            workspace_repo_relative(ws, Some("docs/readme.md")),
            Some(RepoPath::new("docs/readme.md".to_string()).unwrap())
        );
    }

    #[test]
    fn workspace_repo_relative_none_or_empty() {
        let ws = Uuid::new_v4();
        assert_eq!(workspace_repo_relative(ws, None), None);
        assert_eq!(workspace_repo_relative(ws, Some("/")), None);
    }

    #[test]
    fn desired_path_candidates_yields_slug_and_desired_path() {
        let base = Slug::new("foo".to_string()).unwrap();
        let parent = DesiredPath::new("bar");
        let candidates: Vec<_> =
            desired_path_candidates(&base, Some(&parent), DocumentType::Document, 2).collect();
        assert_eq!(
            candidates,
            vec![
                (Slug::new("foo".to_string()).unwrap(), DesiredPath::new("bar/foo.md")),
                (Slug::new("foo-2".to_string()).unwrap(), DesiredPath::new("bar/foo-2.md")),
            ]
        );
    }

    #[test]
    fn desired_path_candidates_for_folder_omits_md_extension() {
        let base = Slug::new("foo".to_string()).unwrap();
        let parent = DesiredPath::new("bar/");
        let candidates: Vec<_> =
            desired_path_candidates(&base, Some(&parent), DocumentType::Folder, 2).collect();
        assert_eq!(
            candidates,
            vec![
                (Slug::new("foo".to_string()).unwrap(), DesiredPath::new("bar/foo")),
                (Slug::new("foo-2".to_string()).unwrap(), DesiredPath::new("bar/foo-2")),
            ]
        );
    }

    #[test]
    fn desired_path_candidates_with_zero_attempts_is_empty() {
        let base = Slug::new("foo".to_string()).unwrap();
        let candidates: Vec<_> =
            desired_path_candidates(&base, None, DocumentType::Document, 0).collect();
        assert!(candidates.is_empty());
    }

    #[test]
    fn from_parent_and_slug_handles_root_parent() {
        let slug = Slug::new("foo".to_string()).unwrap();
        let root = DesiredPath::root();
        assert_eq!(
            DesiredPath::from_parent_and_slug(Some(&root), &slug, DocumentType::Document),
            DesiredPath::new("foo.md")
        );
    }

    #[test]
    fn parent_desired_path_extracts_parent_segment() {
        assert_eq!(
            parent_desired_path(&DesiredPath::new("a/b.md")),
            Some(DesiredPath::new("a"))
        );
        assert_eq!(parent_desired_path(&DesiredPath::new("b.md")), None);
    }

    #[test]
    fn slug_from_desired_path_strips_md_extension_only_when_present() {
        assert_eq!(
            slug_from_desired_path(&DesiredPath::new("a/b.md"))
                .unwrap()
                .as_str(),
            "b"
        );
        assert_eq!(
            slug_from_desired_path(&DesiredPath::new("a/b"))
                .unwrap()
                .as_str(),
            "b"
        );
        assert_eq!(
            slug_from_desired_path(&DesiredPath::new("a/b.md.backup"))
                .unwrap()
                .as_str(),
            "b.md.backup"
        );
    }

    #[test]
    fn slug_from_desired_path_rejects_trailing_slash_and_empty_slug() {
        assert!(slug_from_desired_path(&DesiredPath::new("a/b/")).is_err());
        assert!(slug_from_desired_path(&DesiredPath::new(".md")).is_err());
    }

    #[test]
    fn normalize_repo_path_trims_and_standardizes() {
        assert_eq!(
            normalize_repo_path("//docs//foo.md"),
            Some("docs/foo.md".to_string())
        );
        assert_eq!(
            normalize_repo_path("notes/./bar.md"),
            Some("notes/bar.md".to_string())
        );
        let user = Uuid::new_v4();
        let path = format!(r"{}\notes\foo.md", user);
        assert_eq!(
            normalize_repo_path(&path),
            Some(format!("{}/notes/foo.md", user))
        );
    }

    #[test]
    fn normalize_repo_path_rejects_traversal_and_empty() {
        assert!(normalize_repo_path("../secret").is_none());
        assert!(normalize_repo_path("foo/../bar").is_none());
        assert!(normalize_repo_path("").is_none());
        assert!(normalize_repo_path("/").is_none());
    }
}
