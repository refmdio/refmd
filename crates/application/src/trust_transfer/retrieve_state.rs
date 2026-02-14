//! Retrieve Trust State Command
//!
//! New device retrieves encrypted trust state submitted by an existing device.

use domain::encryption::DeviceId;
use domain::identity::UserId;
use domain::transfer_nonce::{TransferStateError, TransferStateStore};
use std::sync::Arc;
use thiserror::Error;

use crate::dto::EncryptedTransferStateDto;

/// Retrieve state command
#[derive(Debug)]
pub struct RetrieveStateCommand {
    /// User ID
    pub user_id: UserId,
    /// Device ID (the new device retrieving the state)
    pub device_id: DeviceId,
}

/// Retrieve state result
#[derive(Debug)]
pub struct RetrieveStateResult {
    /// Encrypted trust state
    pub encrypted_state: EncryptedTransferStateDto,
}

/// Retrieve state error
#[derive(Debug, Error)]
pub enum RetrieveStateError {
    #[error("trust state not found or expired")]
    NotFound,

    #[error("state store error")]
    StoreError,
}

impl crate::types::AppError for RetrieveStateError {
    fn is_not_found(&self) -> bool {
        matches!(self, RetrieveStateError::NotFound)
    }
}

impl From<TransferStateError> for RetrieveStateError {
    fn from(e: TransferStateError) -> Self {
        match e {
            TransferStateError::NotFound => RetrieveStateError::NotFound,
            TransferStateError::StoreError => RetrieveStateError::StoreError,
        }
    }
}

/// Retrieve state handler
pub struct RetrieveStateHandler {
    state_store: Arc<dyn TransferStateStore>,
}

impl RetrieveStateHandler {
    pub fn new(state_store: Arc<dyn TransferStateStore>) -> Self {
        Self { state_store }
    }

    pub async fn handle(
        &self,
        command: RetrieveStateCommand,
    ) -> Result<RetrieveStateResult, RetrieveStateError> {
        // Retrieve and consume the state (single-use), convert domain → DTO
        let domain_state = self
            .state_store
            .retrieve_and_consume(command.user_id, command.device_id)
            .await?;

        Ok(RetrieveStateResult {
            encrypted_state: domain_state.into(),
        })
    }
}
