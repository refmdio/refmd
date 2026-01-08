//! E2EE migration service.
//!
//! This service handles the server-side encryption of existing plaintext data
//! during the E2EE migration process.

pub mod types;

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;
use tracing::{info, warn};
use uuid::Uuid;

use crate::core::services::errors::ServiceError;
use crate::identity::ports::migration_repository::MigrationRepository;
use crate::identity::ports::migration_tx_runner::{run_migration_tx, MigrationTx, MigrationTxRunner};

pub use types::*;

/// Encryption function signature.
/// Takes (key, plaintext) and returns (ciphertext, nonce).
pub type EncryptFn = fn(&[u8], &[u8]) -> Result<(Vec<u8>, [u8; 24]), anyhow::Error>;

/// Migration service for E2EE.
pub struct MigrationService {
    migration_repo: Arc<dyn MigrationRepository>,
    tx_runner: Arc<dyn MigrationTxRunner>,
    encrypt_fn: EncryptFn,
}

/// Service facade trait for E2EE migration.
#[async_trait]
pub trait MigrationServiceFacade: Send + Sync {
    /// Execute the full migration for a user.
    ///
    /// This encrypts all of the user's documents and files using the provided keys.
    /// The operation is atomic - either all data is encrypted or none is.
    async fn migrate_user_data(
        &self,
        user_id: Uuid,
        request: MigrationRequest,
    ) -> Result<MigrationResult, ServiceError>;

    /// Check if migration is needed for a user.
    async fn needs_migration(&self, user_id: Uuid) -> Result<bool, ServiceError>;
}

impl MigrationService {
    pub fn new(
        migration_repo: Arc<dyn MigrationRepository>,
        tx_runner: Arc<dyn MigrationTxRunner>,
    ) -> Self {
        Self {
            migration_repo,
            tx_runner,
            encrypt_fn: default_encrypt_fn,
        }
    }

    /// Create with a custom encryption function (for testing).
    #[cfg(test)]
    pub fn with_encrypt_fn(mut self, encrypt_fn: EncryptFn) -> Self {
        self.encrypt_fn = encrypt_fn;
        self
    }
}

#[async_trait]
impl MigrationServiceFacade for MigrationService {
    async fn migrate_user_data(
        &self,
        user_id: Uuid,
        request: MigrationRequest,
    ) -> Result<MigrationResult, ServiceError> {
        // Get all documents and files for the user (outside transaction for read-only ops)
        let documents = self
            .migration_repo
            .list_user_documents(user_id)
            .await
            .map_err(ServiceError::from)?;

        let files = self
            .migration_repo
            .list_user_files(user_id)
            .await
            .map_err(ServiceError::from)?;

        let encrypt_fn = self.encrypt_fn;

        // Execute all write operations within a transaction
        let result = run_migration_tx(self.tx_runner.as_ref(), move |tx| {
            Box::pin(async move {
                migrate_user_data_in_tx(tx, user_id, request, documents, files, encrypt_fn).await
            })
        })
        .await
        .map_err(|e| ServiceError::Unexpected(e))?;

        Ok(result)
    }

    async fn needs_migration(&self, user_id: Uuid) -> Result<bool, ServiceError> {
        // Check using the transaction runner (reads from users table)
        let result = run_migration_tx(self.tx_runner.as_ref(), move |tx| {
            Box::pin(async move {
                let completed = tx.user_keys().is_e2ee_setup_completed(user_id).await?;
                Ok(!completed)
            })
        })
        .await
        .map_err(|e| ServiceError::Unexpected(e))?;

        Ok(result)
    }
}

/// Execute migration within a transaction.
async fn migrate_user_data_in_tx(
    tx: &mut dyn MigrationTx,
    user_id: Uuid,
    request: MigrationRequest,
    documents: Vec<crate::identity::ports::migration_repository::MigrationDocument>,
    files: Vec<crate::identity::ports::migration_repository::MigrationFile>,
    encrypt_fn: EncryptFn,
) -> anyhow::Result<MigrationResult> {
    // Check if already migrated
    let already_completed = tx.user_keys().is_e2ee_setup_completed(user_id).await?;

    if already_completed {
        info!(user_id = %user_id, "User already completed E2EE migration");
        return Ok(MigrationResult {
            documents_encrypted: 0,
            files_encrypted: 0,
            updates_cleared: 0,
            status: MigrationStatus::AlreadyCompleted,
        });
    }

    info!(user_id = %user_id, "Starting E2EE migration");

    let mut documents_encrypted = 0;
    let mut files_encrypted = 0;
    let mut updates_cleared: u64 = 0;

    // Encrypt each document
    for doc in &documents {
        let dek = request.document_deks.get(&doc.id).ok_or_else(|| {
            warn!(document_id = %doc.id, "Missing DEK for document");
            anyhow::anyhow!("missing DEK for document")
        })?;

        // Validate DEK length
        if dek.len() != 32 {
            anyhow::bail!("invalid DEK length");
        }

        // Encrypt title
        let (encrypted_title, title_nonce) = encrypt_title(encrypt_fn, dek, &doc.title)?;

        tx.migration()
            .update_encrypted_title(doc.id, &encrypted_title, &title_nonce)
            .await?;

        // Get and encrypt snapshot if exists
        if let Some(snapshot) = tx.migration().get_document_snapshot(doc.id).await? {
            let (encrypted_snapshot, snapshot_nonce) =
                encrypt_snapshot(encrypt_fn, dek, &snapshot.data)?;

            // Get current max seq for seq_at_snapshot
            let max_seq = tx
                .migration()
                .get_document_max_seq(doc.id)
                .await?
                .unwrap_or(0);

            tx.migration()
                .upsert_encrypted_snapshot(doc.id, &encrypted_snapshot, &snapshot_nonce, max_seq)
                .await?;

            // Clear plaintext updates
            let cleared = tx.migration().clear_plaintext_updates(doc.id).await?;
            updates_cleared += cleared;
        }

        // Clear plaintext title
        tx.migration().clear_plaintext_title(doc.id).await?;

        // Store encrypted DEK
        if let Some(encrypted_dek) = request.encrypted_document_deks.get(&doc.id) {
            tx.document_keys()
                .upsert_encrypted_dek(
                    doc.id,
                    &encrypted_dek.encrypted_dek,
                    &encrypted_dek.nonce,
                    1, // Initial key version
                )
                .await?;
        }

        documents_encrypted += 1;
    }

    // Encrypt each file's metadata
    for file in &files {
        let dek = request.document_deks.get(&file.document_id).ok_or_else(|| {
            warn!(file_id = %file.id, document_id = %file.document_id, "Missing DEK for file's document");
            anyhow::anyhow!("missing DEK for file's document")
        })?;

        let (encrypted_metadata, metadata_nonce, encrypted_hash) =
            encrypt_file_metadata(encrypt_fn, dek, &file.filename, file.content_type.as_deref())?;

        tx.migration()
            .update_encrypted_file_metadata(file.id, &encrypted_metadata, &metadata_nonce, &encrypted_hash)
            .await?;

        // Clear plaintext metadata
        tx.migration().clear_plaintext_file_metadata(file.id).await?;

        files_encrypted += 1;
    }

    // Store workspace KEKs for all members
    for (workspace_id, member_keks) in &request.encrypted_workspace_keks {
        for member_kek in member_keks {
            tx.workspace_keys()
                .upsert_encrypted_kek(
                    *workspace_id,
                    member_kek.user_id,
                    &member_kek.encrypted_kek,
                    1, // Initial key version
                )
                .await?;
        }
    }

    // Mark migration as completed
    tx.user_keys().mark_e2ee_setup_completed(user_id).await?;

    info!(
        user_id = %user_id,
        documents_encrypted,
        files_encrypted,
        updates_cleared,
        "E2EE migration completed"
    );

    Ok(MigrationResult {
        documents_encrypted,
        files_encrypted,
        updates_cleared,
        status: MigrationStatus::Completed,
    })
}

/// Encrypt a document's title.
fn encrypt_title(
    encrypt_fn: EncryptFn,
    dek: &[u8],
    title: &str,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let (ciphertext, nonce) = encrypt_fn(dek, title.as_bytes())?;
    Ok((ciphertext, nonce.to_vec()))
}

/// Encrypt a document's Yjs snapshot.
fn encrypt_snapshot(
    encrypt_fn: EncryptFn,
    dek: &[u8],
    snapshot: &[u8],
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let (ciphertext, nonce) = encrypt_fn(dek, snapshot)?;
    Ok((ciphertext, nonce.to_vec()))
}

/// Encrypt file metadata (filename, content_type).
fn encrypt_file_metadata(
    encrypt_fn: EncryptFn,
    dek: &[u8],
    filename: &str,
    content_type: Option<&str>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>, String)> {
    let metadata = json!({
        "filename": filename,
        "content_type": content_type
    });
    let metadata_bytes = serde_json::to_vec(&metadata)?;

    let (ciphertext, nonce) = encrypt_fn(dek, &metadata_bytes)?;

    // Create encrypted hash (hash of the encrypted metadata)
    let encrypted_hash = format!("enc:{}", hex::encode(&ciphertext[..16.min(ciphertext.len())]));

    Ok((ciphertext, nonce.to_vec(), encrypted_hash))
}

/// Default encryption function using XChaCha20-Poly1305.
fn default_encrypt_fn(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 24]), anyhow::Error> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305, XNonce,
    };
    use rand::RngCore;

    if key.len() != 32 {
        anyhow::bail!("Invalid key length: expected 32, got {}", key.len());
    }

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Invalid key: {}", e))?;

    let mut nonce_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    Ok((ciphertext, nonce_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_progress_percent() {
        let progress = MigrationProgress {
            total_documents: 10,
            processed_documents: 5,
            total_files: 10,
            processed_files: 5,
        };
        assert!((progress.percent() - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_migration_progress_empty() {
        let progress = MigrationProgress::default();
        assert!((progress.percent() - 100.0).abs() < 0.01);
    }
}
