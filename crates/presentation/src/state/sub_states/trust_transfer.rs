use std::sync::Arc;

use super::*;

/// Sub-state for trust transfer routes
#[derive(Clone)]
pub struct TrustTransferSubState {
    pub transfer_nonce_store: DynTransferNonceStore,
    pub transfer_state_store: DynTransferStateStore,
    pub device_repo: DynDeviceRepository,
    pub pending_device_repo: DynPendingDeviceRepository,
    pub device_event_bus: DynDeviceEventBus,
}

impl_from_ref!(TrustTransferSubState {
    transfer_nonce_store, transfer_state_store, device_repo,
    pending_device_repo, device_event_bus,
});
