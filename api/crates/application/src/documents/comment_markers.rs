use std::collections::HashSet;

pub(crate) fn strip_comment_markers(content: &str, markers: &[String]) -> String {
    let mut out = content.to_string();
    let mut seen = HashSet::new();
    for marker in markers {
        if marker.is_empty() || !seen.insert(marker.as_str()) {
            continue;
        }
        out = out.replace(marker, "");
    }
    out
}

pub(crate) fn strip_comment_markers_from_bytes(bytes: Vec<u8>, markers: &[String]) -> Vec<u8> {
    match String::from_utf8(bytes) {
        Ok(content) => strip_comment_markers(&content, markers).into_bytes(),
        Err(error) => error.into_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_comment_markers_removes_persisted_core_comment_anchors() {
        let content = "alpha<!--comment:abc_DEF-123--> beta\n<!--comment:550e8400-e29b-41d4-a716-446655440000-->gamma";
        let markers = vec![
            "<!--comment:abc_DEF-123-->".to_string(),
            "<!--comment:550e8400-e29b-41d4-a716-446655440000-->".to_string(),
        ];

        assert_eq!(
            strip_comment_markers(content, &markers),
            "alpha beta\ngamma"
        );
    }

    #[test]
    fn strip_comment_markers_leaves_unowned_marker_looking_content_untouched() {
        let content = "alpha<!--comment:manual--> beta<!--comment:owned-->";
        let markers = vec!["<!--comment:owned-->".to_string()];

        assert_eq!(
            strip_comment_markers(content, &markers),
            "alpha<!--comment:manual--> beta"
        );
    }

    #[test]
    fn strip_comment_markers_ignores_empty_and_duplicate_markers() {
        let content = "alpha<!--comment:owned--> beta<!--comment:owned-->";
        let markers = vec![
            String::new(),
            "<!--comment:owned-->".to_string(),
            "<!--comment:owned-->".to_string(),
        ];

        assert_eq!(strip_comment_markers(content, &markers), "alpha beta");
    }

    #[test]
    fn strip_comment_markers_from_bytes_preserves_invalid_utf8() {
        let bytes = vec![0xff, b'a', b'b', b'c'];

        assert_eq!(strip_comment_markers_from_bytes(bytes.clone(), &[]), bytes);
    }
}
