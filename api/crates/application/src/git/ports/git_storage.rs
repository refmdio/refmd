use std::collections::HashMap;
use std::pin::Pin;

use async_trait::async_trait;
use futures_core::Stream;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

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

pub type PackStream = Pin<Box<dyn Stream<Item = PortResult<PackBlob>> + Send>>;

#[async_trait]
pub trait GitStorage: Send + Sync {
    async fn latest_commit(&self, user_id: Uuid) -> PortResult<Option<CommitMeta>>;
    async fn store_pack(&self, user_id: Uuid, pack: &[u8], meta: &CommitMeta) -> PortResult<()>;
    async fn load_pack_chain(&self, user_id: Uuid, until: Option<&[u8]>) -> PortResult<PackStream>;
    async fn put_blob(&self, key: &BlobKey, data: &[u8]) -> PortResult<()>;
    async fn fetch_blob(&self, key: &BlobKey) -> PortResult<Vec<u8>>;
    async fn commit_meta(&self, user_id: Uuid, commit_id: &[u8]) -> PortResult<Option<CommitMeta>>;
    async fn restore_commit_meta(&self, user_id: Uuid, meta: &CommitMeta) -> PortResult<()>;
    async fn fetch_pack_for_commit(
        &self,
        user_id: Uuid,
        commit_id: &[u8],
    ) -> PortResult<Option<Vec<u8>>>;
    async fn delete_blob(&self, key: &BlobKey) -> PortResult<()>;
    async fn delete_pack(&self, user_id: Uuid, commit_id: &[u8]) -> PortResult<()>;
    async fn set_latest_commit(&self, user_id: Uuid, meta: Option<&CommitMeta>) -> PortResult<()>;
    async fn delete_all(&self, user_id: Uuid) -> PortResult<()>;
}

pub fn encode_commit_id(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn decode_commit_id(hex: &str) -> PortResult<CommitId> {
    if !hex.len().is_multiple_of(2) {
        return Err(anyhow::anyhow!("invalid commit id length").into());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let chars: Vec<char> = hex.chars().collect();
    for chunk in chars.chunks(2) {
        let [hi, lo] = chunk else {
            return Err(anyhow::anyhow!("invalid commit id").into());
        };
        let hi = hi
            .to_digit(16)
            .ok_or_else(|| anyhow::anyhow!("invalid commit id"))?;
        let lo = lo
            .to_digit(16)
            .ok_or_else(|| anyhow::anyhow!("invalid commit id"))?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}
