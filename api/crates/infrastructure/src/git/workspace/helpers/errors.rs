pub(in super::super) fn missing_metadata_commit(err: &anyhow::Error) -> Option<String> {
    let needle = "metadata not found for commit ";
    for cause in err.chain() {
        let msg = cause.to_string();
        if let Some(idx) = msg.find(needle) {
            let start = idx + needle.len();
            let rest = &msg[start..];
            let commit: String = rest
                .chars()
                .take_while(|ch| ch.is_ascii_hexdigit())
                .collect();
            if !commit.is_empty() {
                return Some(commit);
            }
        }
    }
    None
}
