use crate::application::ports::tagging_repository::TaggingRepository;
use once_cell::sync::Lazy;
use regex::Regex;
use uuid::Uuid;

static TAG_RE: Lazy<Regex> = Lazy::new(|| {
    // same ranges as frontend hashtag plugin
    Regex::new(r"\B#([a-zA-Z0-9\u{3040}-\u{309F}\u{30A0}-\u{30FF}\u{4E00}-\u{9FAF}\u{3400}-\u{4DBF}\u{AC00}-\u{D7AF}_-]+)").unwrap()
});

pub async fn update_document_tags<R: TaggingRepository + ?Sized>(
    repo: &R,
    doc_id: Uuid,
    owner_id: Uuid,
    content: &str,
) -> anyhow::Result<()> {
    use std::collections::HashSet;
    let mut set: HashSet<String> = HashSet::new();
    for cap in TAG_RE.captures_iter(content) {
        if let Some(m) = cap.get(1) {
            let mut t = m.as_str().to_string();
            if t.len() > 64 {
                t.truncate(64);
            }
            if !t.is_empty() {
                set.insert(t.to_lowercase());
            }
        }
    }
    // clear existing
    repo.clear_document_tags(doc_id).await?;
    // insert tags and associations
    for name in set {
        // upsert tag (global unique by name)
        let tag_id = repo.upsert_tag_return_id(&name).await?;
        // associate if document belongs to owner
        if repo.owner_doc_exists(doc_id, owner_id).await? {
            repo.associate_document_tag(doc_id, tag_id).await?;
        }
    }
    Ok(())
}
