use anyhow::{anyhow, bail};
use uuid::Uuid;

/// Convert an absolute storage path (/workspace_id/... or workspace_id/...) to a repo-relative path.
pub fn repo_relative_from_storage(workspace_id: Uuid, storage_path: &str) -> Option<String> {
    let trimmed = storage_path.trim_start_matches('/');
    let owner_prefix = workspace_id.to_string();
    let remainder = trimmed
        .strip_prefix(&owner_prefix)
        .map(|rest| rest.trim_start_matches('/'))
        .unwrap_or(trimmed);
    if remainder.is_empty() {
        None
    } else {
        Some(remainder.to_string())
    }
}

/// Convert a stored doc path (which may be absolute or prefixed with workspace id) to repo-relative.
pub fn workspace_repo_relative(workspace_id: Uuid, stored_path: Option<&str>) -> Option<String> {
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
        Some(repo.to_string())
    }
}

pub fn slugify(title: &str) -> String {
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

pub fn build_desired_path(
    parent_desired_path: Option<&str>,
    slug: &str,
    doc_type: &str,
) -> String {
    let prefix = parent_desired_path
        .filter(|p| !p.is_empty())
        .map(|p| {
            if p.ends_with('/') {
                p.to_string()
            } else {
                format!("{p}/")
            }
        })
        .unwrap_or_default();

    let desired = if doc_type == "folder" {
        format!("{prefix}{slug}")
    } else {
        format!("{prefix}{slug}.md")
    };
    desired.trim_start_matches('/').to_string()
}

pub fn parent_desired_path(desired_path: &str) -> Option<String> {
    let mut parts = desired_path.rsplitn(2, '/');
    parts.next()?; // skip current file/folder
    parts.next().map(|parent| parent.to_string())
}

pub fn slug_from_desired_path(desired_path: &str) -> anyhow::Result<String> {
    let segment = desired_path
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
    Ok(slug.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_relative_strips_workspace_prefix() {
        let ws = Uuid::new_v4();
        let p = format!("{}/foo/bar.md", ws);
        assert_eq!(
            repo_relative_from_storage(ws, &p),
            Some("foo/bar.md".to_string())
        );
        let with_slash = format!("/{}/foo/bar.md", ws);
        assert_eq!(
            repo_relative_from_storage(ws, &with_slash),
            Some("foo/bar.md".to_string())
        );
    }

    #[test]
    fn repo_relative_keeps_plain_paths() {
        let ws = Uuid::new_v4();
        assert_eq!(
            repo_relative_from_storage(ws, "foo/bar.md"),
            Some("foo/bar.md".to_string())
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
            Some("docs/readme.md".to_string())
        );
        let with_slash = format!("/{}/docs/readme.md", ws);
        assert_eq!(
            workspace_repo_relative(ws, Some(&with_slash)),
            Some("docs/readme.md".to_string())
        );
    }

    #[test]
    fn workspace_repo_relative_passes_through_repo_paths() {
        let ws = Uuid::new_v4();
        assert_eq!(
            workspace_repo_relative(ws, Some("docs/readme.md")),
            Some("docs/readme.md".to_string())
        );
    }

    #[test]
    fn workspace_repo_relative_none_or_empty() {
        let ws = Uuid::new_v4();
        assert_eq!(workspace_repo_relative(ws, None), None);
        assert_eq!(workspace_repo_relative(ws, Some("/")), None);
    }
}
