//! WebSocket message types for server-client communication

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

/// Outgoing message from server to client (sent via per-connection mpsc channels)
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum WsOutMessage {
    /// Initial document load response
    #[serde(rename = "document")]
    Document {
        snapshot: Option<WsSnapshotData>,
        updates: Vec<WsUpdateData>,
        #[serde(rename = "snapshotProofChain")]
        snapshot_proof_chain: Vec<WsSnapshotProof>,
    },

    /// Remote snapshot broadcast to other clients
    #[serde(rename = "snapshot")]
    Snapshot {
        #[serde(rename = "snapshotId")]
        snapshot_id: String,
        snapshot: WsSnapshotEnvelope,
    },

    /// Snapshot saved confirmation (to sender)
    #[serde(rename = "snapshot-saved")]
    SnapshotSaved {
        #[serde(rename = "snapshotId")]
        snapshot_id: String,
    },

    /// Snapshot save failed (to sender, includes server latest state)
    #[serde(rename = "snapshot-save-failed")]
    SnapshotSaveFailed {
        snapshot: Option<WsSnapshotData>,
        updates: Vec<WsUpdateData>,
        #[serde(rename = "snapshotProofChain")]
        snapshot_proof_chain: Vec<WsSnapshotProof>,
    },

    /// Remote update broadcast to other clients
    #[serde(rename = "update")]
    Update(WsUpdateEnvelope),

    /// Update saved confirmation (to sender)
    #[serde(rename = "update-saved")]
    UpdateSaved {
        #[serde(rename = "snapshotId")]
        snapshot_id: String,
        clock: i32,
        version: i64,
    },

    /// Update save failed (to sender)
    #[serde(rename = "update-save-failed")]
    UpdateSaveFailed {
        #[serde(rename = "snapshotId")]
        snapshot_id: String,
        clock: i32,
        #[serde(rename = "requiresNewSnapshot")]
        requires_new_snapshot: bool,
    },

    /// Ephemeral message broadcast
    #[serde(rename = "ephemeral-message")]
    EphemeralMessage(WsEphemeralEnvelope),

    /// Document not found
    #[serde(rename = "document-not-found")]
    DocumentNotFound,

    /// Unauthorized access
    #[serde(rename = "unauthorized")]
    Unauthorized,

    /// Server error
    #[serde(rename = "document-error")]
    DocumentError,

    /// Validation error (sent when an inbound message fails validation)
    #[serde(rename = "validation-error")]
    ValidationError {
        #[serde(rename = "messageType")]
        message_type: String,
        detail: String,
    },
}

/// Snapshot data from DB (for document/snapshot-save-failed messages)
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsSnapshotData {
    pub id: String,
    pub document_id: String,
    pub latest_version: i64,
    pub data: String,
    pub nonce: String,
    pub key_version: i32,
    pub signature: String,
    pub ciphertext_hash: String,
    pub clocks: HashMap<String, i64>,
    pub parent_snapshot_update_clocks: HashMap<String, i64>,
    pub parent_snapshot_proof: String,
    pub created_by_device: String,
    pub public_data: serde_json::Value,
    pub created_at: String,
}

/// Update data from DB (for document message)
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsUpdateData {
    pub update_data: String,
    pub nonce: String,
    pub key_version: i32,
    pub update_hash: String,
    pub signature: String,
    pub timestamp: i64,
    pub snapshot_id: String,
    pub clock: i32,
    pub version: i64,
    pub device_signing_pub_key: String,
    pub public_data: serde_json::Value,
}

/// Snapshot proof chain entry
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsSnapshotProof {
    pub snapshot_id: String,
    pub ciphertext_hash: String,
    pub parent_snapshot_proof: String,
}

/// Client → Server envelope (raw JSON from WS)
///
/// Parsed from a single `serde_json::Value` to avoid double-deserializing
/// the same JSON text. `raw_public_data` retains the original JSON for
/// signature verification and DB storage.
#[derive(Debug, ToSchema)]
#[schema(rename_all = "camelCase")]
pub struct WsInEnvelope {
    pub ciphertext: String,
    pub nonce: String,
    pub signature: String,
    pub public_data: WsInPublicData,
    /// Raw JSON value of `publicData` — internal field for signature verification
    /// and DB storage. Not part of the wire format (derived from `publicData`).
    #[schema(ignore)]
    pub raw_public_data: serde_json::Value,
}

impl WsInEnvelope {
    /// Parse from raw JSON text in a single pass.
    pub fn from_text(text: &str) -> Result<Self, serde_json::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RawEnvelope {
            ciphertext: String,
            nonce: String,
            signature: String,
            public_data: serde_json::Value,
        }

        let raw: RawEnvelope = serde_json::from_str(text)?;
        let public_data: WsInPublicData = serde_json::from_value(raw.public_data.clone())?;

        Ok(Self {
            ciphertext: raw.ciphertext,
            nonce: raw.nonce,
            signature: raw.signature,
            public_data,
            raw_public_data: raw.public_data,
        })
    }
}

/// Public data from client envelope — used to determine message type
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsInPublicData {
    pub doc_id: String,
    pub device_id: String,
    pub signing_pub_key: String,

    // Common fields
    #[serde(default)]
    pub key_version: Option<i32>,

    // Snapshot fields
    /// Client-generated snapshot ID (included in signed publicData for snapshots)
    #[serde(default)]
    pub snapshot_id: Option<String>,
    #[serde(default)]
    pub parent_snapshot_id: Option<String>,
    #[serde(default)]
    pub parent_snapshot_proof: Option<String>,
    #[serde(default)]
    pub parent_snapshot_update_clocks: Option<HashMap<String, i64>>,

    // Update fields
    #[serde(default)]
    pub ref_snapshot_id: Option<String>,
    #[serde(default)]
    pub clock: Option<i32>,
    /// Client-generated Unix ms timestamp (used for update_hash verification)
    #[serde(default)]
    pub timestamp: Option<i64>,
    /// Client-computed update_hash (BLAKE3 of JCS-canonical fields, base64url)
    #[serde(default)]
    pub update_hash: Option<String>,
}

/// Envelope relayed to other clients (snapshot)
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsSnapshotEnvelope {
    pub ciphertext: String,
    pub nonce: String,
    pub signature: String,
    pub public_data: serde_json::Value,
}

/// Envelope relayed to other clients (update)
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsUpdateEnvelope {
    pub ciphertext: String,
    pub nonce: String,
    pub signature: String,
    pub public_data: serde_json::Value,
    /// Server-assigned version (added by server)
    pub version: i64,
}

/// Envelope relayed to other clients (ephemeral)
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WsEphemeralEnvelope {
    pub ciphertext: String,
    pub nonce: String,
    pub signature: String,
    pub public_data: serde_json::Value,
}

/// Determine the type of incoming message from publicData fields
pub enum IncomingMessageType {
    Snapshot,
    Update,
    Ephemeral,
}

impl WsInEnvelope {
    pub fn message_type(&self) -> IncomingMessageType {
        if self.public_data.parent_snapshot_id.is_some() {
            IncomingMessageType::Snapshot
        } else if self.public_data.ref_snapshot_id.is_some() {
            IncomingMessageType::Update
        } else {
            IncomingMessageType::Ephemeral
        }
    }
}
