//! Slug generation utilities

use std::sync::Arc;

use domain::workspace::{Slug, SlugError, WorkspaceRepository};

/// Normalize a string into a slug: lowercase, replace non-alphanumeric with hyphens,
/// collapse consecutive hyphens, trim leading/trailing hyphens.
fn normalize_slug(input: &str) -> String {
    input
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Generate a URL-safe slug from a name/title.
///
/// Falls back to "untitled" if empty, truncates at 100 chars.
pub fn generate_slug(input: &str) -> String {
    let slug = normalize_slug(input);

    if slug.is_empty() {
        "untitled".to_string()
    } else if slug.len() > 100 {
        slug[..100].to_string()
    } else {
        slug
    }
}

/// Generate a `Slug` domain type from a name.
///
/// Falls back to "workspace" if the input produces an empty slug.
pub fn generate_workspace_slug(name: &str) -> Result<Slug, SlugError> {
    let slug_str = normalize_slug(name);

    if slug_str.is_empty() {
        return Slug::new("workspace");
    }

    Slug::new(slug_str)
}

/// Generate a random 4-character hex suffix using CSPRNG.
pub fn generate_random_suffix() -> Result<String, getrandom::Error> {
    let mut buf = [0u8; 2];
    getrandom::fill(&mut buf)?;
    Ok(format!("{:04x}", u16::from_be_bytes(buf)))
}

/// Ensure a workspace slug is unique by appending random suffixes if needed.
///
/// Checks `slug_exists` on the workspace repo. If the base slug is taken,
/// tries up to 10 random suffixes. Returns the first available slug.
/// On exhaustion, returns `None` so callers can decide on fallback behavior.
pub async fn ensure_unique_workspace_slug<WR>(
    workspace_repo: &Arc<WR>,
    base_slug: Slug,
) -> Result<Option<Slug>, WR::Error>
where
    WR: WorkspaceRepository + ?Sized,
{
    if !workspace_repo.slug_exists(&base_slug).await? {
        return Ok(Some(base_slug));
    }

    // Try with random suffixes
    for _ in 0..10 {
        // generate_random_suffix uses getrandom which won't realistically fail,
        // but if it does we just skip this attempt.
        let suffix = match generate_random_suffix() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let new_slug_str = format!("{}-{}", base_slug.as_str(), suffix);
        if let Ok(new_slug) = Slug::new(new_slug_str)
            && !workspace_repo.slug_exists(&new_slug).await?
        {
            return Ok(Some(new_slug));
        }
    }

    Ok(None)
}
