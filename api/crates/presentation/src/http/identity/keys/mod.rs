mod handlers;
pub mod types;

use axum::routing::{get, post};
use axum::Router;

use crate::context::AppContext;

pub use handlers::{
    get_e2ee_status, get_encrypted_private_key, get_master_key_backup, get_my_public_key,
    get_user_public_key, mark_e2ee_setup_complete, register_public_key,
    store_encrypted_private_key, store_master_key_backup, E2eeStatusResponse,
};
pub use types::*;

pub mod openapi {
    pub use super::handlers::*;
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        // Public key endpoints
        .route("/me/keys", get(get_my_public_key).post(register_public_key))
        .route("/users/:user_id/keys", get(get_user_public_key))
        // Master key backup endpoints
        .route(
            "/me/master-key/backup",
            get(get_master_key_backup).post(store_master_key_backup),
        )
        // Encrypted private key endpoints
        .route(
            "/me/private-key/encrypted",
            get(get_encrypted_private_key).post(store_encrypted_private_key),
        )
        // E2EE setup status
        .route("/me/e2ee/setup-complete", post(mark_e2ee_setup_complete))
        .route("/me/e2ee/status", get(get_e2ee_status))
        .with_state(ctx)
}
