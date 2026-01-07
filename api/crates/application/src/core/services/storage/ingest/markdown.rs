use super::*;

#[derive(Debug, Clone)]
pub(super) struct MarkdownIngestPayload {
    pub(super) encrypted_hash: String,
    pub(super) size: i64,
}

/// Parse encrypted file payload (RME1 format)
pub(super) fn parse_markdown_payload(bytes: Vec<u8>) -> anyhow::Result<MarkdownIngestPayload> {
    // Validate RME1 magic number
    if bytes.len() < 4 || &bytes[0..4] != RME1_MAGIC {
        anyhow::bail!("Invalid RME1 format: missing or invalid magic number");
    }

    let encrypted_hash = sha256_hex(&bytes);
    let size = bytes.len() as i64;

    Ok(MarkdownIngestPayload {
        encrypted_hash,
        size,
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
    }

    #[test]
    fn rejects_invalid_magic() {
        let bytes = b"XXXX invalid data".to_vec();
        let result = parse_markdown_payload(bytes);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_too_short_data() {
        let bytes = b"RM".to_vec();
        let result = parse_markdown_payload(bytes);
        assert!(result.is_err());
    }
}
