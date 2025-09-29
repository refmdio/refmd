use std::collections::HashMap;
use std::pin::Pin;

use async_trait::async_trait;
use futures_core::Stream;
use uuid::Uuid;

pub type CommitId = Vec<u8>;

#[derive(Debug, Clone)]
pub struct CommitMeta {
    pub commit_id: CommitId,
    pub parent_commit_id: Option<CommitId>,
    pub message: Option<String>,
    pub author_name: Option<String>,
    pub author_email: Option<String>,
    pub committed_at: chrono::DateTime<chrono::Utc>,
    pub pack_key: String,
    pub file_hash_index: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct PackBlob {
    pub commit_id: CommitId,
    pub bytes: Vec<u8>,
    pub pack_key: String,
}

#[derive(Debug, Clone)]
pub struct BlobKey {
    pub path: String,
}

pub type PackStream = Pin<Box<dyn Stream<Item = anyhow::Result<PackBlob>> + Send>>;

#[async_trait]
pub trait GitStorage: Send + Sync {
    async fn latest_commit(&self, user_id: Uuid) -> anyhow::Result<Option<CommitMeta>>;
    async fn store_pack(&self, user_id: Uuid, pack: &[u8], meta: &CommitMeta)
    -> anyhow::Result<()>;
    async fn load_pack_chain(
        &self,
        user_id: Uuid,
        until: Option<&[u8]>,
    ) -> anyhow::Result<PackStream>;
    async fn put_blob(&self, key: &BlobKey, data: &[u8]) -> anyhow::Result<()>;
    async fn fetch_blob(&self, key: &BlobKey) -> anyhow::Result<Vec<u8>>;
    async fn delete_all(&self, user_id: Uuid) -> anyhow::Result<()>;
}

pub fn encode_commit_id(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn decode_commit_id(hex: &str) -> anyhow::Result<CommitId> {
    if hex.len() % 2 != 0 {
        anyhow::bail!("invalid commit id length");
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let chars: Vec<char> = hex.chars().collect();
    for chunk in chars.chunks(2) {
        let hi = chunk
            .get(0)
            .ok_or_else(|| anyhow::anyhow!("invalid commit id"))?;
        let lo = chunk
            .get(1)
            .ok_or_else(|| anyhow::anyhow!("invalid commit id"))?;
        let byte = u8::from_str_radix(&format!("{}{}", hi, lo), 16)?;
        out.push(byte);
    }
    Ok(out)
}
