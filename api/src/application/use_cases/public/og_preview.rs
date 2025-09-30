use once_cell::sync::Lazy;
use regex::Regex;
use uuid::Uuid;

use crate::application::ports::{
    public_repository::PublicRepository, realtime_port::RealtimeEngine,
};

pub struct PublicOgPreview {
    pub title: String,
    pub summary: String,
}

pub struct GeneratePublicOgPreview<'a, R: PublicRepository + ?Sized, RT: RealtimeEngine + ?Sized> {
    pub repo: &'a R,
    pub realtime: &'a RT,
}

impl<'a, R: PublicRepository + ?Sized, RT: RealtimeEngine + ?Sized>
    GeneratePublicOgPreview<'a, R, RT>
{
    pub async fn execute(
        &self,
        owner_name: &str,
        doc_id: Uuid,
    ) -> anyhow::Result<Option<PublicOgPreview>> {
        let meta = match self
            .repo
            .get_public_meta_by_owner_and_id(owner_name, doc_id)
            .await?
        {
            Some(meta) => meta,
            None => return Ok(None),
        };

        let content = self
            .realtime
            .get_content(&doc_id.to_string())
            .await?
            .unwrap_or_default();

        let summary = summarize_markdown(&content)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("Public document shared by @{}", owner_name));

        let raw_title = meta.1.trim();
        let title = if raw_title.is_empty() {
            format!("@{} • RefMD", owner_name)
        } else {
            format!("{} • {} on RefMD", raw_title, owner_name)
        };

        Ok(Some(PublicOgPreview { title, summary }))
    }
}

static RE_CODE_BLOCK: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)```[\s\S]*?```").expect("valid code block regex"));
static RE_INLINE_CODE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"`[^`]*`").expect("valid inline code regex"));
static RE_IMAGE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"!\[[^\]]*\]\([^)]*\)").expect("valid image regex"));
static RE_LINK: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\[[^\]]*\]\(([^)]*)\)").expect("valid link regex"));
static RE_MARKDOWN_CHARS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[\*_>#`~\-]").expect("valid markdown char regex"));

fn summarize_markdown(input: &str) -> Option<String> {
    if input.trim().is_empty() {
        return None;
    }

    let without_blocks = RE_CODE_BLOCK.replace_all(input, " ");
    let without_inline = RE_INLINE_CODE.replace_all(&without_blocks, " ");
    let without_images = RE_IMAGE.replace_all(&without_inline, " ");
    let restored_links = RE_LINK.replace_all(&without_images, |caps: &regex::Captures<'_>| {
        caps.get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| " ".to_string())
    });
    let cleaned = RE_MARKDOWN_CHARS.replace_all(&restored_links, " ");
    let normalized = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");

    if normalized.is_empty() {
        return None;
    }

    let summary: String = normalized.chars().take(200).collect();
    Some(summary)
}
