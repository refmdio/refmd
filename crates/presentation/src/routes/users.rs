//! User routes

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};
use application::domain::identity::{
    SessionRepository, UserRepository, UserSettingsRepository,
};
use application::identity::{RegisterUserCommand, RegisterUserHandler};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use crate::AppState;

/// Create user routes
pub fn routes<U, S, US>(state: AppState<U, S, US>) -> Router
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
{
    Router::new()
        .route("/", post(register_user::<U, S, US>))
        .with_state(state)
}

/// Register user request
#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterUserRequest {
    /// User email address
    #[schema(example = "user@example.com")]
    pub email: String,
    /// User display name
    #[schema(example = "John Doe")]
    pub name: String,
}

/// Register user response
#[derive(Debug, Serialize, ToSchema)]
pub struct RegisterUserResponse {
    /// User ID (UUID)
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub id: String,
    /// User email address
    #[schema(example = "user@example.com")]
    pub email: String,
    /// User display name
    #[schema(example = "John Doe")]
    pub name: String,
}

/// Error response
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    /// Error message
    #[schema(example = "email already exists")]
    pub error: String,
}

/// Register a new user
///
/// Creates a new user account with the provided email and name.
#[utoipa::path(
    post,
    path = "/api/users",
    request_body = RegisterUserRequest,
    responses(
        (status = 201, description = "User created successfully", body = RegisterUserResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 409, description = "Email already exists", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    tag = "users"
)]
pub async fn register_user<U, S, US>(
    State(state): State<AppState<U, S, US>>,
    Json(request): Json<RegisterUserRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
{
    let user_repo = state.user_repo();
    let settings_repo = state.user_settings_repo();
    let handler = RegisterUserHandler::new(user_repo, settings_repo);

    let command = RegisterUserCommand {
        email: request.email,
        name: request.name,
    };

    match handler.handle(command).await {
        Ok(result) => {
            let response = RegisterUserResponse {
                id: result.user.id.to_string(),
                email: result.user.email.to_string(),
                name: result.user.name,
            };
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(e) => {
            let status = if e.is_conflict() {
                StatusCode::CONFLICT
            } else if e.is_bad_request() {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, Json(ErrorResponse { error: e.to_string() })).into_response()
        }
    }
}
