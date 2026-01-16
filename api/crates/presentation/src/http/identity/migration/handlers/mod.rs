//! HTTP handlers for E2EE migration.

use axum::{extract::State, Json};

use crate::context::IdentityContext;
use crate::http::error::ApiError;
use crate::http::extractors::AuthedUser;
use application::core::services::errors::ServiceError;

use super::types::{MigrateRequest, MigrationResponse};

fn map_migration_error(err: ServiceError) -> ApiError {
    match &err {
        ServiceError::Conflict => ApiError::conflict("migration_already_completed"),
        ServiceError::BadRequest(msg) => ApiError::bad_request(*msg),
        _ => crate::http::error::map_service_error(err, "migration_service_error"),
    }
}

/// Migrate user data to E2EE.
///
/// This endpoint receives encryption keys from the client and encrypts
/// all of the user's existing plaintext data on the server.
///
/// The operation is atomic - either all data is encrypted or none is.
#[utoipa::path(
    post,
    path = "/api/me/encryption/migrate",
    tag = "E2EE",
    request_body = MigrateRequest,
    responses(
        (status = 200, body = MigrationResponse, description = "Migration completed successfully"),
        (status = 400, description = "Invalid request (e.g., missing DEK for document)"),
        (status = 409, description = "Migration already completed"),
        (status = 500, description = "Migration failed")
    )
)]
pub async fn migrate(
    State(ctx): State<IdentityContext>,
    auth: AuthedUser,
    Json(payload): Json<MigrateRequest>,
) -> Result<Json<MigrationResponse>, ApiError> {
    let request = payload.decode().map_err(|e| ApiError::bad_request(e))?;

    let service = ctx.migration_service();
    let result = service
        .migrate_user_data(auth.user_id, request)
        .await
        .map_err(map_migration_error)?;

    Ok(Json(MigrationResponse::from(result)))
}

/// Check if migration is needed for the current user.
#[utoipa::path(
    get,
    path = "/api/me/encryption/needs-migration",
    tag = "E2EE",
    responses(
        (status = 200, body = NeedsMigrationResponse)
    )
)]
pub async fn needs_migration(
    State(ctx): State<IdentityContext>,
    auth: AuthedUser,
) -> Result<Json<NeedsMigrationResponse>, ApiError> {
    let service = ctx.migration_service();
    let needs = service
        .needs_migration(auth.user_id)
        .await
        .map_err(map_migration_error)?;

    Ok(Json(NeedsMigrationResponse { needs_migration: needs }))
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NeedsMigrationResponse {
    pub needs_migration: bool,
}
