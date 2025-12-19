use super::*;

#[derive(Debug, Clone)]
pub(super) struct MarkdownIngestPayload {
    pub(super) doc_id_hint: Option<Uuid>,
    pub(super) body: String,
    pub(super) content_hash: String,
}

#[derive(Debug, Deserialize)]
struct MarkdownFrontMatter {
    id: Option<Uuid>,
}

pub(super) fn parse_markdown_payload(bytes: Vec<u8>) -> anyhow::Result<MarkdownIngestPayload> {
    let content_hash = sha256_hex(&bytes);
    // Accept lossy UTF-8 to avoid retry storms on malformed files; non-UTF8 bytes become U+FFFD.
    let text = String::from_utf8_lossy(&bytes).to_string();
    let trimmed = text.trim_start_matches('\u{feff}');
    if let Some((front, body)) = split_front_matter(trimmed)
        && let Ok(front_matter) = serde_yaml::from_str::<MarkdownFrontMatter>(front)
        && let Some(doc_id) = front_matter.id
    {
        return Ok(MarkdownIngestPayload {
            doc_id_hint: Some(doc_id),
            body: body.to_string(),
            content_hash,
        });
    }
    Ok(MarkdownIngestPayload {
        doc_id_hint: None,
        body: trimmed.to_string(),
        content_hash,
    })
}

fn split_front_matter(input: &str) -> Option<(&str, &str)> {
    let after_open = input
        .strip_prefix("---\r\n")
        .or_else(|| input.strip_prefix("---\n"))?;
    if let Some((front_len, body_start)) = find_front_matter_end(after_open) {
        let front = &after_open[..front_len];
        let body = &after_open[body_start..];
        return Some((front, body));
    }
    None
}

fn find_front_matter_end(s: &str) -> Option<(usize, usize)> {
    let bytes = s.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'\n' {
            let after_newline = &s[idx + 1..];
            if after_newline.starts_with("---") {
                let mut body_start = idx + 1 + 3;
                let mut remainder = &s[body_start..];
                // Skip any trailing newlines so we don't feed extra blank lines
                // back into the realtime layer when the projection re-imports.
                while remainder.starts_with("\r\n") || remainder.starts_with('\n') {
                    if remainder.starts_with("\r\n") {
                        body_start += 2;
                        let (_, rest) = remainder.split_at(2);
                        remainder = rest;
                    } else {
                        body_start += 1;
                        let (_, rest) = remainder.split_at(1);
                        remainder = rest;
                    }
                }
                return Some((idx, body_start));
            }
        }
        idx += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_body_when_front_matter_has_no_id() {
        let markdown = "---\ntitle: Foo\n---\n\nBody".to_string();
        let payload = parse_markdown_payload(markdown.clone().into_bytes()).unwrap();
        assert!(payload.doc_id_hint.is_none());
        assert_eq!(payload.body, markdown);
    }

    #[test]
    fn extracts_id_when_front_matter_is_valid() {
        let doc_id = Uuid::new_v4();
        let markdown = format!("---\nid: {}\n---\n\nHello", doc_id);
        let payload = parse_markdown_payload(markdown.into_bytes()).unwrap();
        assert_eq!(payload.doc_id_hint, Some(doc_id));
        assert_eq!(payload.body.trim_start_matches('\n'), "Hello");
    }
}
