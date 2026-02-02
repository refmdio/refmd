//! Authentication routes

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{AppendHeaders, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use application::domain::document::DocumentRepository;
use application::domain::encryption::{
    DocumentEncryptedKeyRepository, KdfParams, UserEncryptedIdentityKeyRepository,
    UserEncryptedMasterKeyRepository, UserIdentityPublicKeyRepository,
    WorkspaceEncryptedKeyRepository,
};
use application::domain::identity::{SessionRepository, UserRepository, UserSettingsRepository};
use application::domain::workspace::{
    WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRoleRepository,
};
use application::identity::{
    GetCurrentUserHandler, GetCurrentUserQuery, GetSaltHandler, GetSaltQuery,
    LoginPasswordUserCommand, LoginPasswordUserHandler,
    RegisterPasswordUserAtomicCommand, RegisterPasswordUserAtomicHandler,
    RegistrationService,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AppState;

/// Create auth routes
pub fn routes<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>(
    state: AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>,
) -> Router
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    Router::new()
        .route("/salt", get(get_salt::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>))
        .route("/register", post(register::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>))
        .route("/login", post(login::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>))
        .route("/logout", post(logout::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>))
        .route("/me", get(me::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>))
        .with_state(state)
}

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
    /// Salt for KDF (base64 encoded, 32 bytes)
    #[schema(example = "base64-encoded-salt")]
    pub salt: String,
    /// KDF type (always "argon2id")
    #[schema(example = "argon2id")]
    pub kdf_type: String,
    /// KDF parameters
    pub kdf_params: KdfParamsResponse,
}

/// KDF parameters response
#[derive(Debug, Serialize, ToSchema)]
pub struct KdfParamsResponse {
    /// Memory cost in KiB
    #[schema(example = 65536)]
    pub memory_cost: u32,
    /// Time cost (iterations)
    #[schema(example = 3)]
    pub time_cost: u32,
    /// Parallelism factor
    #[schema(example = 4)]
    pub parallelism: u32,
}

impl From<KdfParams> for KdfParamsResponse {
    fn from(params: KdfParams) -> Self {
        Self {
            memory_cost: params.memory_cost,
            time_cost: params.time_cost,
            parallelism: params.parallelism,
        }
    }
}

/// Error response
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthErrorResponse {
    /// Error message
    #[schema(example = "invalid email")]
    pub error: String,
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
    ),
    tag = "auth"
)]
pub async fn get_salt<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>>,
    Query(params): Query<GetSaltQueryParams>,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    // Use application layer handler
    let handler = GetSaltHandler::new(
        state.user_repo(),
        state.user_encrypted_master_key_repo(),
        std::sync::Arc::new(*state.server_secret()),
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
            let status = if e.is_bad_request() {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, Json(AuthErrorResponse { error: e.to_string() })).into_response()
        }
    }
}

/// Register password user request
#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
    /// User email address
    #[schema(example = "user@example.com")]
    pub email: String,
    /// User display name
    #[schema(example = "John Doe")]
    pub name: String,
    /// authKey for login (base64url encoded)
    #[schema(example = "base64url-encoded-auth-key")]
    pub auth_key: String,
    /// Salt for KDF (base64url encoded, 32 bytes)
    #[schema(example = "base64url-encoded-salt")]
    pub salt: String,
    /// Encrypted UMK (base64url encoded)
    #[schema(example = "base64url-encoded-encrypted-umk")]
    pub encrypted_umk: String,
    /// UMK nonce (base64url encoded)
    #[schema(example = "base64url-encoded-nonce")]
    pub umk_nonce: String,
    /// Recovery encrypted UMK (base64url encoded)
    #[schema(example = "base64url-encoded-recovery-encrypted-umk")]
    pub recovery_encrypted_umk: String,
    /// Recovery nonce (base64url encoded)
    #[schema(example = "base64url-encoded-recovery-nonce")]
    pub recovery_nonce: String,
    /// ECDH public key (base64url encoded, 32 bytes)
    #[schema(example = "base64url-encoded-ecdh-public-key")]
    pub ecdh_public_key: String,
    /// Signing public key (base64url encoded, 32 bytes)
    #[schema(example = "base64url-encoded-signing-public-key")]
    pub signing_public_key: String,
    /// Encrypted ECDH private key (base64url encoded)
    #[schema(example = "base64url-encoded-encrypted-ecdh-private")]
    pub encrypted_ecdh_private: String,
    /// Encrypted ECDH private key nonce (base64url encoded)
    #[schema(example = "base64url-encoded-nonce")]
    pub encrypted_ecdh_private_nonce: String,
    /// Encrypted signing private key (base64url encoded)
    #[schema(example = "base64url-encoded-encrypted-signing-private")]
    pub encrypted_signing_private: String,
    /// Encrypted signing private key nonce (base64url encoded)
    #[schema(example = "base64url-encoded-nonce")]
    pub encrypted_signing_private_nonce: String,
}

/// Register response
#[derive(Debug, Serialize, ToSchema)]
pub struct RegisterResponse {
    /// User ID (UUID)
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub id: String,
    /// User email address
    #[schema(example = "user@example.com")]
    pub email: String,
}

/// Register a new password user
///
/// Creates a new user account with password authentication and E2EE keys.
/// All encryption is performed client-side; server stores encrypted data only.
/// Registration is atomic - all entities are created in a single transaction.
#[utoipa::path(
    post,
    path = "/api/auth/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "User registered successfully", body = RegisterResponse),
        (status = 400, description = "Invalid request", body = AuthErrorResponse),
        (status = 409, description = "Email already exists", body = AuthErrorResponse),
        (status = 500, description = "Internal server error", body = AuthErrorResponse),
    ),
    tag = "auth"
)]
pub async fn register<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>>,
    Json(request): Json<RegisterRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    // Decode base64url fields
    let salt = match base64_url::decode(&request.salt) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid salt encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let encrypted_umk = match base64_url::decode(&request.encrypted_umk) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid encrypted_umk encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let umk_nonce = match base64_url::decode(&request.umk_nonce) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid umk_nonce encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let recovery_encrypted_umk = match base64_url::decode(&request.recovery_encrypted_umk) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid recovery_encrypted_umk encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let recovery_nonce = match base64_url::decode(&request.recovery_nonce) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid recovery_nonce encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let ecdh_public_key = match base64_url::decode(&request.ecdh_public_key) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid ecdh_public_key encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let signing_public_key = match base64_url::decode(&request.signing_public_key) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid signing_public_key encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let encrypted_ecdh_private = match base64_url::decode(&request.encrypted_ecdh_private) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid encrypted_ecdh_private encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let encrypted_ecdh_private_nonce = match base64_url::decode(&request.encrypted_ecdh_private_nonce) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid encrypted_ecdh_private_nonce encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let encrypted_signing_private = match base64_url::decode(&request.encrypted_signing_private) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid encrypted_signing_private encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let encrypted_signing_private_nonce = match base64_url::decode(&request.encrypted_signing_private_nonce) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid encrypted_signing_private_nonce encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Use atomic handler for transactional registration
    let handler = RegisterPasswordUserAtomicHandler::new(
        state.user_repo(),
        state.workspace_repo(),
        state.registration_service(),
    );

    let command = RegisterPasswordUserAtomicCommand {
        email: request.email.clone(),
        name: request.name,
        auth_key: request.auth_key,
        salt,
        encrypted_umk,
        umk_nonce,
        recovery_encrypted_umk,
        recovery_nonce,
        ecdh_public_key,
        signing_public_key,
        encrypted_ecdh_private,
        encrypted_ecdh_private_nonce,
        encrypted_signing_private,
        encrypted_signing_private_nonce,
    };

    match handler.handle(command).await {
        Ok(result) => {
            let response = RegisterResponse {
                id: result.user.id.to_string(),
                email: result.user.email.to_string(),
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
            (status, Json(AuthErrorResponse { error: e.to_string() })).into_response()
        }
    }
}

/// Login request
#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    /// User email address
    #[schema(example = "user@example.com")]
    pub email: String,
    /// authKey for authentication (base64url encoded)
    #[schema(example = "base64url-encoded-auth-key")]
    pub auth_key: String,
    /// Remember me flag for extended session duration
    #[schema(example = false)]
    pub remember_me: bool,
}

/// Login response
///
/// Session token is set via HttpOnly cookie, not in JSON body.
#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    /// Session expiration timestamp
    pub expires_at: String,
    /// User ID
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub user_id: String,
    /// User email
    #[schema(example = "user@example.com")]
    pub email: String,
    /// Encrypted UMK (base64url encoded)
    #[schema(example = "base64url-encoded-encrypted-umk")]
    pub encrypted_umk: String,
    /// UMK nonce (base64url encoded)
    #[schema(example = "base64url-encoded-nonce")]
    pub umk_nonce: String,
    /// Encrypted ECDH private key (base64url encoded)
    #[schema(example = "base64url-encoded-encrypted-ecdh-private")]
    pub encrypted_ecdh_private: String,
    /// Encrypted ECDH private key nonce (base64url encoded)
    #[schema(example = "base64url-encoded-nonce")]
    pub encrypted_ecdh_private_nonce: String,
    /// Encrypted signing private key (base64url encoded)
    #[schema(example = "base64url-encoded-encrypted-signing-private")]
    pub encrypted_signing_private: String,
    /// Encrypted signing private key nonce (base64url encoded)
    #[schema(example = "base64url-encoded-nonce")]
    pub encrypted_signing_private_nonce: String,
}

/// Session cookie name
pub const SESSION_COOKIE_NAME: &str = "refmd_session";

/// Login with password authentication
///
/// Authenticates a user with email and authKey.
/// Session token is set via HttpOnly cookie (not in response body).
/// Client should derive authKey from password using Argon2id + HKDF.
#[utoipa::path(
    post,
    path = "/api/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful. Session cookie is set.", body = LoginResponse),
        (status = 400, description = "Invalid request", body = AuthErrorResponse),
        (status = 401, description = "Invalid credentials", body = AuthErrorResponse),
        (status = 500, description = "Internal server error", body = AuthErrorResponse),
    ),
    tag = "auth"
)]
pub async fn login<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>>,
    Json(request): Json<LoginRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    let remember_me = request.remember_me;

    let handler = LoginPasswordUserHandler::new(
        state.user_repo(),
        state.session_repo(),
        state.user_encrypted_master_key_repo(),
        state.user_encrypted_identity_key_repo(),
    );

    let command = LoginPasswordUserCommand {
        email: request.email,
        auth_key: request.auth_key,
        remember_me,
        ip_address: None, // TODO: Extract from request headers
        user_agent: None, // TODO: Extract from request headers
    };

    match handler.handle(command).await {
        Ok(result) => {
            // Build HttpOnly cookie
            let cookie = build_session_cookie(
                &result.session_token,
                result.expires_at,
                remember_me,
                state.secure_cookies(),
            );

            let response = LoginResponse {
                expires_at: result.expires_at.to_rfc3339(),
                user_id: result.user.id.to_string(),
                email: result.user.email.to_string(),
                encrypted_umk: base64_url::encode(&result.encrypted_umk),
                umk_nonce: base64_url::encode(&result.umk_nonce),
                encrypted_ecdh_private: base64_url::encode(&result.encrypted_ecdh_private),
                encrypted_ecdh_private_nonce: base64_url::encode(&result.encrypted_ecdh_private_nonce),
                encrypted_signing_private: base64_url::encode(&result.encrypted_signing_private),
                encrypted_signing_private_nonce: base64_url::encode(&result.encrypted_signing_private_nonce),
            };

            (
                StatusCode::OK,
                AppendHeaders([(header::SET_COOKIE, cookie)]),
                Json(response),
            )
                .into_response()
        }
        Err(e) => {
            // Check internal errors first (data inconsistency should be 500)
            let status = if e.is_internal_error() {
                StatusCode::INTERNAL_SERVER_ERROR
            } else if e.is_unauthorized() {
                StatusCode::UNAUTHORIZED
            } else if e.is_bad_request() {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            // Use safe_message() to prevent user enumeration
            (status, Json(AuthErrorResponse { error: e.safe_message().to_string() })).into_response()
        }
    }
}

/// Build session cookie string
fn build_session_cookie(
    token: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
    remember_me: bool,
    secure: bool,
) -> String {
    let mut cookie = format!("{}={}; Path=/api; HttpOnly; SameSite=Lax", SESSION_COOKIE_NAME, token);

    // Add Secure attribute based on runtime configuration
    if secure {
        cookie.push_str("; Secure");
    }

    if remember_me {
        // Set explicit expiration for persistent cookie
        let expires = expires_at.format("%a, %d %b %Y %H:%M:%S GMT");
        cookie.push_str(&format!("; Expires={}", expires));
    }
    // If not remember_me, cookie is a session cookie (deleted when browser closes)

    cookie
}

/// Build cookie string to clear session
fn build_clear_cookie(secure: bool) -> String {
    let mut cookie = format!(
        "{}=; Path=/api; HttpOnly; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        SESSION_COOKIE_NAME
    );

    if secure {
        cookie.push_str("; Secure");
    }

    cookie
}

/// Logout response
#[derive(Debug, Serialize, ToSchema)]
pub struct LogoutResponse {
    /// Success message
    #[schema(example = "logged out")]
    pub message: String,
}

/// Logout and clear session
///
/// Clears the session cookie. Client should also clear DSK from IndexedDB.
#[utoipa::path(
    post,
    path = "/api/auth/logout",
    responses(
        (status = 200, description = "Logout successful", body = LogoutResponse),
    ),
    tag = "auth"
)]
pub async fn logout<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    // Try to invalidate session on server if cookie exists
    if let Some(token) = extract_session_cookie(&headers) {
        let token_hash = crate::auth::hash_session_token(token);
        let session_repo = state.session_repo();

        // Find and delete the session
        if let Ok(Some(session)) = session_repo.find_by_token_hash(&token_hash).await {
            let _ = session_repo.delete(session.id).await;
        }
    }

    // Clear cookie
    let clear_cookie = build_clear_cookie(state.secure_cookies());

    (
        StatusCode::OK,
        AppendHeaders([(header::SET_COOKIE, clear_cookie)]),
        Json(LogoutResponse {
            message: "logged out".to_string(),
        }),
    )
}

/// Extract session token from cookie header
fn extract_session_cookie(headers: &axum::http::HeaderMap) -> Option<&str> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;

    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix(&format!("{}=", SESSION_COOKIE_NAME)) {
            return Some(value);
        }
    }

    None
}

/// Current user response (for session restoration)
#[derive(Debug, Serialize, ToSchema)]
pub struct MeResponse {
    /// User ID
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub user_id: String,
    /// User email
    #[schema(example = "user@example.com")]
    pub email: String,
    /// User display name
    #[schema(example = "John Doe")]
    pub name: String,
    /// Authentication type ("password" or "oauth")
    #[schema(example = "password")]
    pub auth_type: String,
    /// Session expiration timestamp
    pub expires_at: String,
    /// Encrypted UMK (base64url encoded, null for OAuth users)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "base64url-encoded-encrypted-umk")]
    pub encrypted_umk: Option<String>,
    /// UMK nonce (base64url encoded, null for OAuth users)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "base64url-encoded-nonce")]
    pub umk_nonce: Option<String>,
    /// Encrypted ECDH private key (base64url encoded)
    #[schema(example = "base64url-encoded-encrypted-ecdh-private")]
    pub encrypted_ecdh_private: String,
    /// Encrypted ECDH private key nonce (base64url encoded)
    #[schema(example = "base64url-encoded-nonce")]
    pub encrypted_ecdh_private_nonce: String,
    /// Encrypted signing private key (base64url encoded)
    #[schema(example = "base64url-encoded-encrypted-signing-private")]
    pub encrypted_signing_private: String,
    /// Encrypted signing private key nonce (base64url encoded)
    #[schema(example = "base64url-encoded-nonce")]
    pub encrypted_signing_private_nonce: String,
}

/// Get current user info and encrypted keys
///
/// Returns user info and encrypted keys for session restoration.
/// Requires valid session cookie. Used when client has DSK cached but needs encrypted keys.
#[utoipa::path(
    get,
    path = "/api/auth/me",
    responses(
        (status = 200, description = "Current user info", body = MeResponse),
        (status = 401, description = "Not authenticated", body = AuthErrorResponse),
        (status = 500, description = "Internal server error", body = AuthErrorResponse),
    ),
    tag = "auth"
)]
pub async fn me<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, WKR, DKR, RS>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
{
    // Extract session token from cookie
    let token = match crate::auth::extract_session_token(&headers) {
        Ok(t) => t,
        Err(e) => {
            return (StatusCode::UNAUTHORIZED, Json(AuthErrorResponse { error: e.error })).into_response();
        }
    };

    // Hash the token
    let token_hash = crate::auth::hash_session_token(token);

    // Use application layer handler
    let handler = GetCurrentUserHandler::new(
        state.user_repo(),
        state.session_repo(),
        state.user_encrypted_master_key_repo(),
        state.user_encrypted_identity_key_repo(),
    );

    let query = GetCurrentUserQuery { token_hash };

    let result = match handler.handle(query).await {
        Ok(r) => r,
        Err(e) => {
            let status = if e.is_unauthorized() {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return (status, Json(AuthErrorResponse { error: e.to_string() })).into_response();
        }
    };

    let user = result.user;
    let session = result.session;
    let umk = result.encrypted_master_key;
    let identity_keys = result.encrypted_identity_key;

    let is_password_user = umk.is_password_user();
    let auth_type = if is_password_user { "password" } else { "oauth" };

    // Build response with proper handling for OAuth vs password users
    let (encrypted_umk, umk_nonce) = match (&umk.encrypted_umk, &umk.umk_nonce) {
        (Some(enc), Some(nonce)) if !enc.is_empty() => {
            (Some(base64_url::encode(enc)), Some(base64_url::encode(nonce)))
        }
        _ => {
            if is_password_user {
                // Password user without encrypted_umk is a data inconsistency
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AuthErrorResponse { error: "internal server error".to_string() }),
                )
                    .into_response();
            }
            // OAuth users don't have encrypted_umk (they use DSK or recovery key)
            (None, None)
        }
    };

    let response = MeResponse {
        user_id: user.id.to_string(),
        email: user.email.to_string(),
        name: user.name,
        auth_type: auth_type.to_string(),
        expires_at: session.expires_at.to_rfc3339(),
        encrypted_umk,
        umk_nonce,
        encrypted_ecdh_private: base64_url::encode(&identity_keys.encrypted_ecdh_private),
        encrypted_ecdh_private_nonce: base64_url::encode(&identity_keys.encrypted_ecdh_private_nonce),
        encrypted_signing_private: base64_url::encode(&identity_keys.encrypted_signing_private),
        encrypted_signing_private_nonce: base64_url::encode(&identity_keys.encrypted_signing_private_nonce),
    };

    (StatusCode::OK, Json(response)).into_response()
}
