//! Salt endpoint

use application::identity::{GetSaltHandler, GetSaltQuery};
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AuthSubState;
use crate::routes::app_error_response;
use super::{AuthErrorResponse, KdfParamsResponse};

/// Get salt query parameters (HTTP)
#[derive(Debug, Deserialize, ToSchema)]
pub struct GetSaltQueryParams {
    /// User email address
    #[schema(example = "user@example.com")]
    pub email: String,
}

/// Get salt response
#[derive(Debug, Serialize, ToSchema)]
pub struct GetSaltResponse {
    /// Salt for KDF (base64 encoded, 16 bytes per spec)
    #[schema(example = "base64-encoded-salt")]
    pub salt: String,
    /// KDF type (always "argon2id")
    #[schema(example = "argon2id")]
    pub kdf_type: String,
    /// KDF parameters
    pub kdf_params: KdfParamsResponse,
}

/// Get salt and KDF parameters for login
///
/// Returns the salt and KDF parameters needed to derive the master key.
/// For unknown users, returns a deterministic dummy salt to prevent user enumeration.
/// KDF parameters are always the global default settings.
#[utoipa::path(
    get,
    path = "/api/auth/salt",
    params(
        ("email" = String, Query, description = "User email address")
    ),
    responses(
        (status = 200, description = "Salt and KDF parameters", body = GetSaltResponse),
        (status = 400, description = "Invalid email", body = AuthErrorResponse),
        (status = 500, description = "Internal server error", body = AuthErrorResponse),
    ),
    tag = "auth"
)]
pub async fn get_salt(
    State(state): State<AuthSubState>,
    Query(params): Query<GetSaltQueryParams>,
) -> impl IntoResponse {
    let handler = GetSaltHandler::new(
        state.user_repo.clone(),
        state.user_encrypted_master_key_repo.clone(),
        state.server_secret.clone(),
    );

    let query = GetSaltQuery {
        email: params.email,
    };

    match handler.handle(query).await {
        Ok(result) => {
            let response = GetSaltResponse {
                salt: base64_url::encode(&result.salt),
                kdf_type: result.kdf_type,
                kdf_params: result.kdf_params.into(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            app_error_response!(e, AuthErrorResponse, bad_request)
        }
    }
}
