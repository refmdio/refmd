use crate::application::ports::linkgraph_repository::LinkGraphRepository;
use once_cell::sync::Lazy;
use regex::Regex;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub enum LinkType {
    Reference,
    Embed,
    Mention,
}

impl LinkType {
    fn as_str(&self) -> &'static str {
        match self {
            LinkType::Reference => "reference",
            LinkType::Embed => "embed",
            LinkType::Mention => "mention",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum LinkTarget {
    Id(Uuid),
    Title(String),
}

#[derive(Debug, Clone)]
struct DocumentLink {
    target: LinkTarget,
    link_type: LinkType,
    link_text: Option<String>,
    position_start: i32,
    position_end: i32,
}

static WIKI_LINK_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\[\[([^\[\]|]+)(?:\|([^\[\]]+))?\]\]").unwrap());
static EMBED_LINK_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"!\[\[([^\[\]|]+)(?:\|([^\[\]]+))?\]\]").unwrap());
static MENTION_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"@\[\[([^\[\]|]+)(?:\|([^\[\]]+))?\]\]").unwrap());

fn parse_links(content: &str) -> Vec<DocumentLink> {
    let mut links: Vec<DocumentLink> = Vec::new();
    let mut seen: std::collections::HashSet<usize> = std::collections::HashSet::new();

    for cap in EMBED_LINK_REGEX.captures_iter(content) {
        let mat = cap.get(0).unwrap();
        let start = mat.start();
        if seen.contains(&start) {
            continue;
        }
        seen.insert(start);
        let target_text = cap.get(1).unwrap().as_str();
        let display_text = cap.get(2).map(|m| m.as_str().to_string());
        links.push(DocumentLink {
            target: parse_target(target_text),
            link_type: LinkType::Embed,
            link_text: display_text,
            position_start: start as i32,
            position_end: mat.end() as i32,
        });
    }

    for cap in MENTION_REGEX.captures_iter(content) {
        let mat = cap.get(0).unwrap();
        let start = mat.start();
        if seen.contains(&start) {
            continue;
        }
        seen.insert(start);
        let target_text = cap.get(1).unwrap().as_str();
        let display_text = cap.get(2).map(|m| m.as_str().to_string());
        links.push(DocumentLink {
            target: parse_target(target_text),
            link_type: LinkType::Mention,
            link_text: display_text,
            position_start: start as i32,
            position_end: mat.end() as i32,
        });
    }

    for cap in WIKI_LINK_REGEX.captures_iter(content) {
        let mat = cap.get(0).unwrap();
        let start = mat.start();
        if seen.contains(&start) {
            continue;
        }
        let target_text = cap.get(1).unwrap().as_str();
        let display_text = cap.get(2).map(|m| m.as_str().to_string());
        links.push(DocumentLink {
            target: parse_target(target_text),
            link_type: LinkType::Reference,
            link_text: display_text,
            position_start: start as i32,
            position_end: mat.end() as i32,
        });
    }

    links.sort_by_key(|l| l.position_start);
    links
}

fn parse_target(txt: &str) -> LinkTarget {
    let t = txt.trim();
    if let Ok(id) = Uuid::parse_str(t) {
        LinkTarget::Id(id)
    } else {
        LinkTarget::Title(t.to_string())
    }
}

pub async fn update_document_links<R: LinkGraphRepository>(
    repo: &R,
    owner_id: Uuid,
    source_id: Uuid,
    content: &str,
) -> anyhow::Result<()> {
    let links = parse_links(content);
    // Clear previous links for the source
    repo.clear_links_for_source(source_id).await?;

    for link in links {
        // Resolve target by id or title for the same owner
        let target_doc_id: Option<Uuid> = match link.target {
            LinkTarget::Id(id) => {
                if repo.exists_doc_for_owner(id, owner_id).await? {
                    Some(id)
                } else {
                    None
                }
            }
            LinkTarget::Title(title) => {
                repo.find_doc_id_by_owner_and_title(owner_id, &title)
                    .await?
            }
        };

        if let Some(target_id) = target_doc_id {
            repo.upsert_link(
                source_id,
                target_id,
                link.link_type.as_str(),
                link.link_text,
                link.position_start,
                link.position_end,
            )
            .await?;
        }
    }
    Ok(())
}
