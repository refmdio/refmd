use std::pin::Pin;

use futures_util::{Sink, Stream};
use serde::{Deserialize, Serialize};

use super::realtime_port::RealtimeError;

pub type DynRealtimeSink =
    Pin<Box<dyn Sink<Vec<u8>, Error = RealtimeError> + Send + Sync + 'static>>;
pub type DynRealtimeStream =
    Pin<Box<dyn Stream<Item = Result<Vec<u8>, RealtimeError>> + Send + Sync + 'static>>;

// ============================================================================
// E2EE Message Types (secsync-compatible)
// ============================================================================

/// Signature domains for E2EE messages (domain separation)
pub mod signature_domains {
    pub const SNAPSHOT: &str = "refmd_snapshot";
    pub const UPDATE: &str = "refmd_update";
    pub const EPHEMERAL: &str = "refmd_ephemeral";
}

/// E2EE realtime message types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageType {
    Update,
    Snapshot,
    Awareness,
}

/// E2EE realtime message (JSON format over WebSocket)
/// Field names follow secsync specification (camelCase)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RealtimeMessage {
    /// Message type
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    /// Base64-encoded ciphertext (XChaCha20-Poly1305)
    pub ciphertext: String,
    /// Base64-encoded nonce (24 bytes for XChaCha20-Poly1305)
    pub nonce: String,
    /// Base64-encoded Ed25519 signature
    pub signature: String,
    /// Public metadata (not encrypted, but authenticated via signature)
    /// This is a Base64-encoded canonicalized JSON string
    pub public_data: String,
}

/// Update public data structure (for parsing publicData field)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePublicData {
    /// Document ID
    pub doc_id: String,
    /// Ed25519 public key (Base64-encoded, 32 bytes)
    pub pub_key: String,
    /// Reference snapshot ID
    pub ref_snapshot_id: String,
    /// Logical clock for ordering (per client)
    pub clock: u64,
}

/// Snapshot public data structure (for parsing publicData field)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotPublicData {
    /// Document ID
    pub doc_id: String,
    /// Ed25519 public key (Base64-encoded, 32 bytes)
    pub pub_key: String,
    /// Snapshot ID
    pub snapshot_id: String,
    /// Parent snapshot ID
    pub parent_snapshot_id: String,
    /// Parent snapshot proof
    pub parent_snapshot_proof: String,
    /// Update clocks at the time of snapshot (pubKey -> clock)
    pub parent_snapshot_update_clocks: std::collections::HashMap<String, u64>,
}

/// Ephemeral message public data structure (for Awareness)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EphemeralPublicData {
    /// Document ID
    pub doc_id: String,
    /// Ed25519 public key (Base64-encoded, 32 bytes)
    pub pub_key: String,
}

impl RealtimeMessage {
    /// Get the signature domain for this message type
    pub fn signature_domain(&self) -> &'static str {
        match self.msg_type {
            MessageType::Update => signature_domains::UPDATE,
            MessageType::Snapshot => signature_domains::SNAPSHOT,
            MessageType::Awareness => signature_domains::EPHEMERAL,
        }
    }

    /// Parse the publicData field as UpdatePublicData
    pub fn parse_update_public_data(&self) -> anyhow::Result<UpdatePublicData> {
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.public_data,
        )?;
        let json_str = String::from_utf8(decoded)?;
        Ok(serde_json::from_str(&json_str)?)
    }

    /// Parse the publicData field as SnapshotPublicData
    pub fn parse_snapshot_public_data(&self) -> anyhow::Result<SnapshotPublicData> {
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.public_data,
        )?;
        let json_str = String::from_utf8(decoded)?;
        Ok(serde_json::from_str(&json_str)?)
    }

    /// Parse the publicData field as EphemeralPublicData
    pub fn parse_ephemeral_public_data(&self) -> anyhow::Result<EphemeralPublicData> {
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.public_data,
        )?;
        let json_str = String::from_utf8(decoded)?;
        Ok(serde_json::from_str(&json_str)?)
    }
}
