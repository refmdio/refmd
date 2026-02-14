//! Device management routes
//!
//! Endpoints for multi-device support:
//! - Create pending device
//! - Get SAS for verification
//! - Approve device (promote from pending)
//! - List devices
//! - Revoke device
//! - Distribute UMK to device

mod active;
mod events;
mod pending;

pub use active::*;
pub use events::*;
pub use pending::*;

use axum::{
    Router,
    routing::{delete, get, post},
};
use tower_governor::GovernorLayer;

use crate::{AppState, rate_limit::create_device_rate_limit_config};

/// Create device routes
pub fn routes(state: AppState) -> Result<Router, anyhow::Error> {
    // Rate limiting config for device registration
    let device_rate_limit = create_device_rate_limit_config()?;

    // Rate-limited routes (device registration)
    let rate_limited_routes = Router::new()
        .route(
            "/pending",
            post(create_pending_device),
        )
        .layer(GovernorLayer {
            config: device_rate_limit,
        });

    // Non-rate-limited routes (authenticated endpoints)
    let other_routes = Router::new()
        .route(
            "/pending",
            get(list_pending_devices),
        )
        .route(
            "/pending/{id}/sas",
            get(get_sas),
        )
        .route(
            "/pending/{id}/events",
            get(pending_device_events),
        )
        .route(
            "/pending/{id}/approve",
            post(approve_device),
        )
        .route(
            "/pending/{id}",
            delete(reject_pending_device),
        )
        .route(
            "/events",
            get(device_events),
        )
        .route(
            "/",
            get(list_devices),
        )
        .route(
            "/{id}",
            delete(revoke_device),
        )
        .route(
            "/{id}/keys/umk",
            post(distribute_umk)
            .get(get_device_umk),
        );

    Ok(Router::new()
        .merge(rate_limited_routes)
        .merge(other_routes)
        .with_state(state))
}

super::error_response_struct!(DeviceErrorResponse);
