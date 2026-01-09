use super::*;

#[derive(Debug, Clone)]
pub(super) struct MarkdownIngestPayload {
    pub(super) encrypted_hash: String,
    pub(super) size: i64,
    /// True if file is encrypted (RME1 format), false if legacy plaintext
    pub(super) is_encrypted: bool,
}

/// Parse file payload - supports both RME1 encrypted format and legacy plaintext
pub(super) fn parse_markdown_payload(bytes: Vec<u8>) -> anyhow::Result<MarkdownIngestPayload> {
    let is_encrypted = bytes.len() >= 4 && &bytes[0..4] == RME1_MAGIC;

    let encrypted_hash = sha256_hex(&bytes);
    let size = bytes.len() as i64;

    Ok(MarkdownIngestPayload {
        encrypted_hash,
        size,
        is_encrypted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_rme1_format() {
        let mut bytes = b"RME1".to_vec();
        bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x10]); // version + header length
        bytes.extend_from_slice(&[0u8; 16]); // dummy header
        bytes.extend_from_slice(&[0u8; 24]); // dummy content nonce
        bytes.extend_from_slice(b"encrypted content");

        let payload = parse_markdown_payload(bytes.clone()).unwrap();
        assert_eq!(payload.size, bytes.len() as i64);
        assert!(!payload.encrypted_hash.is_empty());
        assert!(payload.is_encrypted);
    }

    #[test]
    fn parses_legacy_plaintext() {
        let bytes = b"# Hello World\n\nThis is plaintext markdown.".to_vec();
        let payload = parse_markdown_payload(bytes.clone()).unwrap();
        assert_eq!(payload.size, bytes.len() as i64);
        assert!(!payload.encrypted_hash.is_empty());
        assert!(!payload.is_encrypted);
    }

    #[test]
    fn parses_short_data_as_plaintext() {
        let bytes = b"RM".to_vec();
        let payload = parse_markdown_payload(bytes.clone()).unwrap();
        assert_eq!(payload.size, bytes.len() as i64);
        assert!(!payload.is_encrypted);
    }
}
