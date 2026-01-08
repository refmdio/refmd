//! Types for E2EE migration service.

use std::collections::HashMap;
use uuid::Uuid;

/// Request to migrate user data to E2EE.
///
/// Contains all the keys needed to encrypt the user's existing data.
#[derive(Debug, Clone)]
pub struct MigrationRequest {
    /// Workspace KEKs (Key Encryption Keys).
    /// Maps workspace_id -> raw KEK (32 bytes).
    pub workspace_keks: HashMap<Uuid, Vec<u8>>,

    /// Document DEKs (Data Encryption Keys).
    /// Maps document_id -> raw DEK (32 bytes).
    pub document_deks: HashMap<Uuid, Vec<u8>>,

    /// Encrypted workspace KEKs to store for each member.
    /// Maps workspace_id -> Vec<(user_id, encrypted_kek, nonce)>.
    pub encrypted_workspace_keks: HashMap<Uuid, Vec<MemberEncryptedKek>>,

    /// Encrypted DEKs to store for each document.
    /// Maps document_id -> (encrypted_dek, nonce).
    pub encrypted_document_deks: HashMap<Uuid, EncryptedDek>,
}

/// Encrypted KEK for a workspace member.
///
/// The KEK is encrypted with the member's ECDH public key.
/// The encryption format (including nonce) is handled by the client.
#[derive(Debug, Clone)]
pub struct MemberEncryptedKek {
    pub user_id: Uuid,
    /// KEK encrypted with user's ECDH public key.
    pub encrypted_kek: Vec<u8>,
}

/// Encrypted DEK for a document.
#[derive(Debug, Clone)]
pub struct EncryptedDek {
    pub encrypted_dek: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Result of the migration process.
#[derive(Debug, Clone)]
pub struct MigrationResult {
    /// Number of documents encrypted.
    pub documents_encrypted: usize,

    /// Number of files with encrypted metadata.
    pub files_encrypted: usize,

    /// Total number of Yjs updates cleared.
    pub updates_cleared: u64,

    /// Migration status.
    pub status: MigrationStatus,
}

/// Status of the migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStatus {
    /// Migration completed successfully.
    Completed,
    /// Migration was already completed before.
    AlreadyCompleted,
}

/// Progress tracking during migration.
#[derive(Debug, Clone, Default)]
pub struct MigrationProgress {
    pub total_documents: usize,
    pub processed_documents: usize,
    pub total_files: usize,
    pub processed_files: usize,
}

impl MigrationProgress {
    pub fn percent(&self) -> f32 {
        let total = self.total_documents + self.total_files;
        if total == 0 {
            return 100.0;
        }
        let done = self.processed_documents + self.processed_files;
        (done as f32 / total as f32) * 100.0
    }
}
