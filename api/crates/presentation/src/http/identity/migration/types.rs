//! HTTP request/response types for E2EE migration.

use std::collections::HashMap;

use base64::Engine;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use application::identity::services::migration::{
    EncryptedDek, MemberEncryptedKek, MigrationRequest, MigrationResult, MigrationStatus,
};

// ============================================================================
// Request Types
// ============================================================================

/// Request to migrate user data to E2EE.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MigrateRequest {
    /// Workspace KEKs (Key Encryption Keys).
    /// Maps workspace_id (string) -> base64-encoded raw KEK.
    pub workspace_keks: HashMap<String, String>,

    /// Document DEKs (Data Encryption Keys).
    /// Maps document_id (string) -> base64-encoded raw DEK.
    pub document_deks: HashMap<String, String>,

    /// Encrypted workspace KEKs to store for each member.
    /// Maps workspace_id (string) -> array of member encrypted KEKs.
    pub encrypted_workspace_keks: HashMap<String, Vec<MemberEncryptedKekRequest>>,

    /// Encrypted DEKs to store for each document.
    /// Maps document_id (string) -> encrypted DEK with nonce.
    pub encrypted_document_deks: HashMap<String, EncryptedDekRequest>,
}

/// Encrypted KEK for a workspace member (request).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MemberEncryptedKekRequest {
    /// User ID.
    pub user_id: String,
    /// Base64-encoded encrypted KEK.
    #[schema(value_type = String, format = "byte")]
    pub encrypted_kek: String,
}

/// Encrypted DEK for a document (request).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedDekRequest {
    /// Base64-encoded encrypted DEK.
    #[schema(value_type = String, format = "byte")]
    pub encrypted_dek: String,
    /// Base64-encoded nonce.
    #[schema(value_type = String, format = "byte")]
    pub nonce: String,
}

impl MigrateRequest {
    /// Decode the request into domain types.
    pub fn decode(&self) -> Result<MigrationRequest, &'static str> {
        let b64 = base64::engine::general_purpose::STANDARD;

        // Decode workspace KEKs
        let mut workspace_keks = HashMap::new();
        for (ws_id, kek_b64) in &self.workspace_keks {
            let ws_uuid = Uuid::parse_str(ws_id).map_err(|_| "invalid_workspace_id")?;
            let kek = b64.decode(kek_b64).map_err(|_| "invalid_base64_kek")?;
            if kek.len() != 32 {
                return Err("invalid_kek_length");
            }
            workspace_keks.insert(ws_uuid, kek);
        }

        // Decode document DEKs
        let mut document_deks = HashMap::new();
        for (doc_id, dek_b64) in &self.document_deks {
            let doc_uuid = Uuid::parse_str(doc_id).map_err(|_| "invalid_document_id")?;
            let dek = b64.decode(dek_b64).map_err(|_| "invalid_base64_dek")?;
            if dek.len() != 32 {
                return Err("invalid_dek_length");
            }
            document_deks.insert(doc_uuid, dek);
        }

        // Decode encrypted workspace KEKs
        let mut encrypted_workspace_keks = HashMap::new();
        for (ws_id, members) in &self.encrypted_workspace_keks {
            let ws_uuid = Uuid::parse_str(ws_id).map_err(|_| "invalid_workspace_id")?;
            let mut member_keks = Vec::new();
            for m in members {
                let user_uuid = Uuid::parse_str(&m.user_id).map_err(|_| "invalid_user_id")?;
                let encrypted_kek = b64
                    .decode(&m.encrypted_kek)
                    .map_err(|_| "invalid_base64_encrypted_kek")?;
                member_keks.push(MemberEncryptedKek {
                    user_id: user_uuid,
                    encrypted_kek,
                });
            }
            encrypted_workspace_keks.insert(ws_uuid, member_keks);
        }

        // Decode encrypted document DEKs
        let mut encrypted_document_deks = HashMap::new();
        for (doc_id, enc_dek) in &self.encrypted_document_deks {
            let doc_uuid = Uuid::parse_str(doc_id).map_err(|_| "invalid_document_id")?;
            let encrypted_dek = b64
                .decode(&enc_dek.encrypted_dek)
                .map_err(|_| "invalid_base64_encrypted_dek")?;
            let nonce = b64
                .decode(&enc_dek.nonce)
                .map_err(|_| "invalid_base64_nonce")?;
            encrypted_document_deks.insert(
                doc_uuid,
                EncryptedDek {
                    encrypted_dek,
                    nonce,
                },
            );
        }

        Ok(MigrationRequest {
            workspace_keks,
            document_deks,
            encrypted_workspace_keks,
            encrypted_document_deks,
        })
    }
}

// ============================================================================
// Response Types
// ============================================================================

/// Response for migration result.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MigrationResponse {
    /// Number of documents encrypted.
    pub documents_encrypted: usize,
    /// Number of files with encrypted metadata.
    pub files_encrypted: usize,
    /// Total number of Yjs updates cleared.
    pub updates_cleared: u64,
    /// Migration status.
    pub status: String,
}

impl From<MigrationResult> for MigrationResponse {
    fn from(result: MigrationResult) -> Self {
        Self {
            documents_encrypted: result.documents_encrypted,
            files_encrypted: result.files_encrypted,
            updates_cleared: result.updates_cleared,
            status: match result.status {
                MigrationStatus::Completed => "completed".to_string(),
                MigrationStatus::AlreadyCompleted => "already_completed".to_string(),
            },
        }
    }
}
