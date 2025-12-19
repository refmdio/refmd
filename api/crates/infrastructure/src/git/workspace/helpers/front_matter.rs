pub(in super::super) fn find_front_matter_end(s: &str) -> Option<(usize, usize)> {
    let bytes = s.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'\n' {
            let after_newline = &s[idx + 1..];
            if after_newline.starts_with("---") {
                let mut body_start = idx + 1 + 3;
                let mut remainder = &s[body_start..];
                // Skip trailing newlines after the closing delimiter to mirror ingest.
                while remainder.starts_with("\r\n") || remainder.starts_with('\n') {
                    if remainder.starts_with("\r\n") {
                        body_start += 2;
                        remainder = &s[body_start..];
                    } else {
                        body_start += 1;
                        remainder = &s[body_start..];
                    }
                }
                return Some((idx, body_start));
            }
        }
        idx += 1;
    }
    None
}

pub(in super::super) fn split_front_matter(input: &str) -> Option<(&str, &str)> {
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

pub(in super::super) fn strip_front_matter_body(
    path: &str,
    text: Option<String>,
) -> Option<String> {
    let txt = text?;
    let lower = path.to_ascii_lowercase();
    let is_markdown = lower.ends_with(".md") || lower.ends_with(".markdown");
    if !is_markdown {
        return Some(txt);
    }
    if let Some((_, body)) = split_front_matter(txt.as_str()) {
        return Some(body.to_string());
    }
    Some(txt)
}

pub(in super::super) fn extract_markdown_body(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let trimmed = text.trim_start_matches('\u{feff}');
    if let Some((_, body)) = split_front_matter(trimmed) {
        return Some(body.to_string());
    }
    Some(trimmed.to_string())
}
