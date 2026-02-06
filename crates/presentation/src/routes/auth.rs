//! Authentication routes

use crate::crypto_validation::{is_valid_ed25519_public_key, is_valid_x25519_public_key};

/// XChaCha20-Poly1305 nonce size in bytes
const XCHACHA20_NONCE_SIZE: usize = 24;

/// Argon2id salt size in bytes (per spec)
const ARGON2_SALT_SIZE: usize = 16;

/// X25519/Ed25519 public key size in bytes
const PUBLIC_KEY_SIZE: usize = 32;

/// Client nonce size in bytes (for SAS verification)
const CLIENT_NONCE_SIZE: usize = 16;

/// Ed25519 signature size in bytes
const ED25519_SIGNATURE_SIZE: usize = 64;

use application::domain::document::{DocumentRepository, DocumentUpdateRepository};
use application::domain::encryption::{
    DeviceEncryptedUMKRepository, DeviceId, DeviceRepository, DeviceType,
    DocumentEncryptedKeyRepository, KdfParams, PendingDeviceRepository,
    UserEncryptedIdentityKeyRepository, UserEncryptedMasterKeyRepository,
    UserIdentityPublicKeyRepository, WorkspaceEncryptedKeyRepository,
};
use application::domain::identity::{SessionRepository, UserRepository, UserSettingsRepository};
use application::domain::workspace::{
    WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRoleRepository,
};
use application::identity::{
    GetCurrentUserHandler, GetCurrentUserQuery, GetRecoveryDataHandler, GetRecoveryDataQuery,
    GetSaltHandler, GetSaltQuery, LoginPasswordUserCommand, LoginPasswordUserHandler,
    RecoverySessionCommand, RecoverySessionHandler, RegisterPasswordUserAtomicCommand,
    RegisterPasswordUserAtomicHandler, RegistrationService,
};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{StatusCode, header, HeaderMap},
    response::{AppendHeaders, IntoResponse},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tower_governor::GovernorLayer;
use utoipa::ToSchema;

use crate::{
    AppState,
    middleware::{CHALLENGE_TTL_SECS, POP_DEVICE_ID_HEADER},
    rate_limit::{create_auth_rate_limit_config, create_register_rate_limit_config},
};
use chrono::{Duration as ChronoDuration, Utc};
use rand::Rng;

/// Create auth routes
pub fn routes<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    state: AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
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
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    // Rate limiting configs
    let register_rate_limit = create_register_rate_limit_config();
    let auth_rate_limit = create_auth_rate_limit_config();

    // Routes with stricter rate limiting (registration)
    let register_routes = Router::new()
        .route(
            "/register",
            post(
                register::<
                    U,
                    S,
                    US,
                    UIP,
                    UEM,
                    UEI,
                    WR,
                    WMR,
                    WRR,
                    DR,
                    DUR,
                    WKR,
                    DKR,
                    RS,
                    DER,
                    PDR,
                    UMKR,
                >,
            ),
        )
        .layer(GovernorLayer {
            config: register_rate_limit,
        });

    // Routes with standard auth rate limiting (login, salt, recovery)
    let auth_rate_limited_routes =
        Router::new()
            .route(
                "/salt",
                get(get_salt::<
                    U,
                    S,
                    US,
                    UIP,
                    UEM,
                    UEI,
                    WR,
                    WMR,
                    WRR,
                    DR,
                    DUR,
                    WKR,
                    DKR,
                    RS,
                    DER,
                    PDR,
                    UMKR,
                >),
            )
            .route(
                "/login",
                post(
                    login::<
                        U,
                        S,
                        US,
                        UIP,
                        UEM,
                        UEI,
                        WR,
                        WMR,
                        WRR,
                        DR,
                        DUR,
                        WKR,
                        DKR,
                        RS,
                        DER,
                        PDR,
                        UMKR,
                    >,
                ),
            )
            .route(
                "/recovery",
                get(get_recovery::<
                    U,
                    S,
                    US,
                    UIP,
                    UEM,
                    UEI,
                    WR,
                    WMR,
                    WRR,
                    DR,
                    DUR,
                    WKR,
                    DKR,
                    RS,
                    DER,
                    PDR,
                    UMKR,
                >),
            )
            .route(
                "/recovery/challenge",
                post(
                    create_recovery_challenge::<
                        U,
                        S,
                        US,
                        UIP,
                        UEM,
                        UEI,
                        WR,
                        WMR,
                        WRR,
                        DR,
                        DUR,
                        WKR,
                        DKR,
                        RS,
                        DER,
                        PDR,
                        UMKR,
                    >,
                ),
            )
            .route(
                "/recovery/session",
                post(
                    create_recovery_session::<
                        U,
                        S,
                        US,
                        UIP,
                        UEM,
                        UEI,
                        WR,
                        WMR,
                        WRR,
                        DR,
                        DUR,
                        WKR,
                        DKR,
                        RS,
                        DER,
                        PDR,
                        UMKR,
                    >,
                ),
            )
            .layer(GovernorLayer {
                config: auth_rate_limit,
            });

    // Routes without rate limiting (authenticated endpoints)
    // pop-challenge is not rate-limited because it already requires:
    // 1. Valid session cookie (authentication)
    // 2. Device ownership verification
    // 3. Device revocation check
    let non_rate_limited_routes = Router::new()
        .route(
            "/logout",
            post(
                logout::<
                    U,
                    S,
                    US,
                    UIP,
                    UEM,
                    UEI,
                    WR,
                    WMR,
                    WRR,
                    DR,
                    DUR,
                    WKR,
                    DKR,
                    RS,
                    DER,
                    PDR,
                    UMKR,
                >,
            ),
        )
        .route(
            "/me",
            get(me::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>),
        )
        .route(
            "/pop-challenge",
            post(
                create_pop_challenge::<
                    U,
                    S,
                    US,
                    UIP,
                    UEM,
                    UEI,
                    WR,
                    WMR,
                    WRR,
                    DR,
                    DUR,
                    WKR,
                    DKR,
                    RS,
                    DER,
                    PDR,
                    UMKR,
                >,
            ),
        );

    Router::new()
        .merge(register_routes)
        .merge(auth_rate_limited_routes)
        .merge(non_rate_limited_routes)
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
    /// Salt for KDF (base64 encoded, 16 bytes per spec)
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
pub async fn get_salt<
    U,
    S,
    US,
    UIP,
    UEM,
    UEI,
    WR,
    WMR,
    WRR,
    DR,
    DUR,
    WKR,
    DKR,
    RS,
    DER,
    PDR,
    UMKR,
>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
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
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
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
            let (status, message) = if e.is_bad_request() {
                (StatusCode::BAD_REQUEST, e.to_string())
            } else {
                tracing::error!("get_salt internal error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            };
            (status, Json(AuthErrorResponse { error: message })).into_response()
        }
    }
}

/// Register password user request
#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
    /// Client-generated User ID (UUID) - required for AAD binding
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub user_id: uuid::Uuid,
    /// User email address
    #[schema(example = "user@example.com")]
    pub email: String,
    /// User display name
    #[schema(example = "John Doe")]
    pub name: String,
    /// authKey for login (base64url encoded)
    #[schema(example = "base64url-encoded-auth-key")]
    pub auth_key: String,
    /// Salt for KDF (base64url encoded, 16 bytes per spec)
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
    /// Device name for the first device
    #[schema(example = "Chrome on MacOS")]
    pub device_name: String,
    /// Device type: "browser", "desktop", or "mobile"
    #[schema(example = "browser")]
    pub device_type: String,
    /// Device ECDH public key (base64url encoded, 32 bytes)
    #[schema(example = "base64url-encoded-device-ecdh-public-key")]
    pub device_ecdh_public_key: String,
    /// Device signing public key (base64url encoded, 32 bytes)
    #[schema(example = "base64url-encoded-device-signing-public-key")]
    pub device_signing_public_key: String,
    /// Device client nonce for SAS (base64url encoded, 16 bytes)
    #[schema(example = "base64url-encoded-device-nonce")]
    pub device_client_nonce: String,
    /// Identity signature over device keys (base64url encoded, 64 bytes Ed25519 signature)
    #[schema(example = "base64url-encoded-identity-signature")]
    pub device_identity_signature: String,
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
    /// Device ID (UUID) - the first registered device
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub device_id: String,
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
pub async fn register<
    U,
    S,
    US,
    UIP,
    UEM,
    UEI,
    WR,
    WMR,
    WRR,
    DR,
    DUR,
    WKR,
    DKR,
    RS,
    DER,
    PDR,
    UMKR,
>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
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
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    // Decode base64url fields with length validation
    let salt = match base64_url::decode(&request.salt) {
        Ok(s) if s.len() == ARGON2_SALT_SIZE => s,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid salt length: expected 16 bytes".to_string(),
                }),
            )
                .into_response();
        }
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
        Ok(s) if s.len() == XCHACHA20_NONCE_SIZE => s,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid umk_nonce length: expected 24 bytes".to_string(),
                }),
            )
                .into_response();
        }
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
        Ok(s) if s.len() == XCHACHA20_NONCE_SIZE => s,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid recovery_nonce length: expected 24 bytes".to_string(),
                }),
            )
                .into_response();
        }
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
        Ok(s) if s.len() == PUBLIC_KEY_SIZE && is_valid_x25519_public_key(&s) => s,
        Ok(s) if s.len() != PUBLIC_KEY_SIZE => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid ecdh_public_key length: expected 32 bytes".to_string(),
                }),
            )
                .into_response();
        }
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid ecdh_public_key: low-order point rejected".to_string(),
                }),
            )
                .into_response();
        }
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
        Ok(s) if s.len() == PUBLIC_KEY_SIZE && is_valid_ed25519_public_key(&s) => s,
        Ok(s) if s.len() != PUBLIC_KEY_SIZE => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid signing_public_key length: expected 32 bytes".to_string(),
                }),
            )
                .into_response();
        }
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid signing_public_key: small-order point rejected".to_string(),
                }),
            )
                .into_response();
        }
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

    let encrypted_ecdh_private_nonce =
        match base64_url::decode(&request.encrypted_ecdh_private_nonce) {
            Ok(s) if s.len() == XCHACHA20_NONCE_SIZE => s,
            Ok(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(AuthErrorResponse {
                        error: "invalid encrypted_ecdh_private_nonce length: expected 24 bytes"
                            .to_string(),
                    }),
                )
                    .into_response();
            }
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

    let encrypted_signing_private_nonce =
        match base64_url::decode(&request.encrypted_signing_private_nonce) {
            Ok(s) if s.len() == XCHACHA20_NONCE_SIZE => s,
            Ok(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(AuthErrorResponse {
                        error: "invalid encrypted_signing_private_nonce length: expected 24 bytes"
                            .to_string(),
                    }),
                )
                    .into_response();
            }
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

    // Decode device fields
    let device_ecdh_public_key = match base64_url::decode(&request.device_ecdh_public_key) {
        Ok(s) if s.len() == PUBLIC_KEY_SIZE && is_valid_x25519_public_key(&s) => s,
        Ok(s) if s.len() != PUBLIC_KEY_SIZE => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid device_ecdh_public_key length: expected 32 bytes".to_string(),
                }),
            )
                .into_response();
        }
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid device_ecdh_public_key: low-order point rejected".to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid device_ecdh_public_key encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let device_signing_public_key = match base64_url::decode(&request.device_signing_public_key) {
        Ok(s) if s.len() == PUBLIC_KEY_SIZE && is_valid_ed25519_public_key(&s) => s,
        Ok(s) if s.len() != PUBLIC_KEY_SIZE => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid device_signing_public_key length: expected 32 bytes"
                        .to_string(),
                }),
            )
                .into_response();
        }
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid device_signing_public_key: small-order point rejected"
                        .to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid device_signing_public_key encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let device_client_nonce = match base64_url::decode(&request.device_client_nonce) {
        Ok(s) if s.len() == CLIENT_NONCE_SIZE => s,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid device_client_nonce length: expected 16 bytes".to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid device_client_nonce encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let device_identity_signature = match base64_url::decode(&request.device_identity_signature) {
        Ok(s) if s.len() == ED25519_SIGNATURE_SIZE => s,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid device_identity_signature length: expected 64 bytes"
                        .to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid device_identity_signature encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Parse device type
    let device_type: DeviceType = match request.device_type.parse() {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid device_type: must be 'browser', 'desktop', or 'mobile'"
                        .to_string(),
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
        user_id: request.user_id,
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
        device_name: request.device_name,
        device_type,
        device_ecdh_public_key,
        device_signing_public_key,
        device_client_nonce,
        device_identity_signature,
    };

    match handler.handle(command).await {
        Ok(result) => {
            let response = RegisterResponse {
                id: result.user.id.to_string(),
                email: result.user.email.to_string(),
                device_id: result.device.id.to_string(),
            };
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(e) => {
            let (status, message) = if e.is_conflict() {
                (StatusCode::CONFLICT, e.to_string())
            } else if e.is_bad_request() {
                (StatusCode::BAD_REQUEST, e.to_string())
            } else {
                tracing::error!("register internal error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            };
            (status, Json(AuthErrorResponse { error: message })).into_response()
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
    /// Device ID for session binding (optional, for existing devices)
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    #[serde(default)]
    pub device_id: Option<String>,
}

/// Login response
///
/// Session token is set via HttpOnly cookie, not in JSON body.
/// Note: Encrypted keys are only returned for verified (registered) devices.
/// New devices must go through the PendingDevice flow to receive keys.
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
    /// Whether user has any registered devices (for PoP enforcement)
    #[schema(example = true)]
    pub has_devices: bool,
    /// Whether the login device is verified (registered and active)
    #[schema(example = true)]
    pub device_verified: bool,
    /// Device ID if verified
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Encrypted keys (only present for verified devices)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys: Option<LoginResponseKeys>,
}

/// Encrypted keys returned only for verified devices
#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponseKeys {
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
pub async fn login<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
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
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    let remember_me = request.remember_me;

    let handler = LoginPasswordUserHandler::new(
        state.user_repo(),
        state.session_repo(),
        state.user_encrypted_master_key_repo(),
        state.user_encrypted_identity_key_repo(),
        state.device_repo(),
    );

    // Parse device_id if provided
    let device_id = request
        .device_id
        .as_ref()
        .and_then(|id| uuid::Uuid::parse_str(id).ok().map(DeviceId::from_uuid));

    // Extract IP: prefer X-Forwarded-For (reverse proxy), fallback to ConnectInfo (direct socket)
    // SECURITY: This assumes deployment behind a trusted reverse proxy (nginx, Cloudflare, etc.)
    // that overwrites X-Forwarded-For. Direct internet exposure would allow header spoofing.
    // IP is used for audit logging only, not for authentication or access control decisions.
    // See: local/docs/v2/07-deployment/web-security.md
    let socket_ip = connect_info.0.ip().to_string();
    let forwarded_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
        });
    let ip_address = Some(
        forwarded_ip
            .unwrap_or(socket_ip)
            .chars()
            .take(45) // IPv6 max length
            .collect::<String>(),
    );

    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(512).collect::<String>());

    let command = LoginPasswordUserCommand {
        email: request.email,
        auth_key: request.auth_key,
        remember_me,
        ip_address,
        user_agent,
        device_id,
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

            // Only include keys if device is verified
            let keys = result.keys.map(|k| LoginResponseKeys {
                encrypted_umk: base64_url::encode(&k.encrypted_umk),
                umk_nonce: base64_url::encode(&k.umk_nonce),
                encrypted_ecdh_private: base64_url::encode(&k.encrypted_ecdh_private),
                encrypted_ecdh_private_nonce: base64_url::encode(&k.encrypted_ecdh_private_nonce),
                encrypted_signing_private: base64_url::encode(&k.encrypted_signing_private),
                encrypted_signing_private_nonce: base64_url::encode(
                    &k.encrypted_signing_private_nonce,
                ),
            });

            let response = LoginResponse {
                expires_at: result.expires_at.to_rfc3339(),
                user_id: result.user.id.to_string(),
                email: result.user.email.to_string(),
                has_devices: result.has_devices,
                device_verified: result.device_verified,
                device_id: result.device_id.map(|d| d.to_string()),
                keys,
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
            (
                status,
                Json(AuthErrorResponse {
                    error: e.safe_message().to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// Get recovery data query parameters (HTTP)
#[derive(Debug, Deserialize, ToSchema)]
pub struct GetRecoveryQueryParams {
    /// User email address
    #[schema(example = "user@example.com")]
    pub email: String,
}

/// Get recovery data response
#[derive(Debug, Serialize, ToSchema)]
pub struct GetRecoveryResponse {
    /// User ID (needed for AAD verification)
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub user_id: String,
    /// Recovery encrypted UMK (base64url encoded)
    #[schema(example = "base64url-encoded-recovery-encrypted-umk")]
    pub recovery_encrypted_umk: String,
    /// Recovery nonce (base64url encoded)
    #[schema(example = "base64url-encoded-recovery-nonce")]
    pub recovery_nonce: String,
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

/// Get recovery data for account recovery
///
/// Returns encrypted UMK (encrypted with recovery key) and encrypted identity keys.
/// Client will decrypt UMK using the recovery key derived from 24-word mnemonic,
/// then use UMK to decrypt identity keys.
#[utoipa::path(
    get,
    path = "/api/auth/recovery",
    params(
        ("email" = String, Query, description = "User email address")
    ),
    responses(
        (status = 200, description = "Recovery data (returns plausible dummy data for non-existent users to prevent enumeration)", body = GetRecoveryResponse),
        (status = 400, description = "Invalid email", body = AuthErrorResponse),
    ),
    tag = "auth"
)]
pub async fn get_recovery<
    U,
    S,
    US,
    UIP,
    UEM,
    UEI,
    WR,
    WMR,
    WRR,
    DR,
    DUR,
    WKR,
    DKR,
    RS,
    DER,
    PDR,
    UMKR,
>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
    Query(params): Query<GetRecoveryQueryParams>,
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
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    let start = tokio::time::Instant::now();

    let handler = GetRecoveryDataHandler::new(
        state.user_repo(),
        state.user_encrypted_master_key_repo(),
        state.user_encrypted_identity_key_repo(),
    );

    let query = GetRecoveryDataQuery {
        email: params.email,
    };

    let result = handler.handle(query).await;

    // Timing attack mitigation: ensure minimum response time
    // to prevent distinguishing existing vs non-existing users
    const MIN_RESPONSE_TIME: std::time::Duration = std::time::Duration::from_millis(50);
    let elapsed = start.elapsed();
    if elapsed < MIN_RESPONSE_TIME {
        tokio::time::sleep(MIN_RESPONSE_TIME - elapsed).await;
    }

    match result {
        Ok(result) => {
            let response = GetRecoveryResponse {
                user_id: result.user_id.to_string(),
                recovery_encrypted_umk: base64_url::encode(&result.recovery_encrypted_umk),
                recovery_nonce: base64_url::encode(&result.recovery_nonce),
                encrypted_ecdh_private: base64_url::encode(&result.encrypted_ecdh_private),
                encrypted_ecdh_private_nonce: base64_url::encode(
                    &result.encrypted_ecdh_private_nonce,
                ),
                encrypted_signing_private: base64_url::encode(&result.encrypted_signing_private),
                encrypted_signing_private_nonce: base64_url::encode(
                    &result.encrypted_signing_private_nonce,
                ),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            if e.is_bad_request() {
                let message = e.to_string();
                (StatusCode::BAD_REQUEST, Json(AuthErrorResponse { error: message })).into_response()
            } else if e.is_not_found() {
                // Anti-enumeration: return dummy data indistinguishable from real data.
                // Client will fail at decryption (wrong recovery key), not at HTTP level.
                use rand::RngCore;
                let mut rng = rand::rng();
                let dummy_id = uuid::Uuid::now_v7();
                let mut dummy_encrypted_umk = vec![0u8; 48]; // 32 bytes + 16 tag
                let mut dummy_nonce = vec![0u8; 24];
                let mut dummy_ecdh_private = vec![0u8; 48];
                let mut dummy_ecdh_nonce = vec![0u8; 24];
                let mut dummy_signing_private = vec![0u8; 48];
                let mut dummy_signing_nonce = vec![0u8; 24];
                rng.fill_bytes(&mut dummy_encrypted_umk);
                rng.fill_bytes(&mut dummy_nonce);
                rng.fill_bytes(&mut dummy_ecdh_private);
                rng.fill_bytes(&mut dummy_ecdh_nonce);
                rng.fill_bytes(&mut dummy_signing_private);
                rng.fill_bytes(&mut dummy_signing_nonce);

                let response = GetRecoveryResponse {
                    user_id: dummy_id.to_string(),
                    recovery_encrypted_umk: base64_url::encode(&dummy_encrypted_umk),
                    recovery_nonce: base64_url::encode(&dummy_nonce),
                    encrypted_ecdh_private: base64_url::encode(&dummy_ecdh_private),
                    encrypted_ecdh_private_nonce: base64_url::encode(&dummy_ecdh_nonce),
                    encrypted_signing_private: base64_url::encode(&dummy_signing_private),
                    encrypted_signing_private_nonce: base64_url::encode(&dummy_signing_nonce),
                };
                (StatusCode::OK, Json(response)).into_response()
            } else {
                tracing::error!("get_recovery internal error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AuthErrorResponse {
                        error: "internal server error".to_string(),
                    }),
                )
                    .into_response()
            }
        }
    }
}

/// Build session cookie string
///
/// Note: Always set Expires attribute regardless of remember_me flag.
/// This ensures sessions persist for 24 hours (or 30 days for remember_me)
/// even when the browser is closed and reopened.
fn build_session_cookie(
    token: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
    _remember_me: bool,
    secure: bool,
) -> String {
    let mut cookie = format!(
        "{}={}; Path=/api; HttpOnly; SameSite=Lax",
        SESSION_COOKIE_NAME, token
    );

    // Add Secure attribute based on runtime configuration
    if secure {
        cookie.push_str("; Secure");
    }

    // Always set Expires attribute so session persists across browser restarts
    // Session duration (24h vs 30d) is controlled by expires_at from application layer
    let expires = expires_at.format("%a, %d %b %Y %H:%M:%S GMT");
    cookie.push_str(&format!("; Expires={}", expires));

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
pub async fn logout<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
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
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
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
pub async fn me<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
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
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    // Extract session token from cookie
    let token = match crate::auth::extract_session_token(&headers) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(AuthErrorResponse { error: e.error }),
            )
                .into_response();
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
            let (status, message) = if e.is_unauthorized() {
                (StatusCode::UNAUTHORIZED, e.to_string())
            } else {
                tracing::error!("get_current_user internal error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            };
            return (status, Json(AuthErrorResponse { error: message })).into_response();
        }
    };

    let user = result.user;
    let session = result.session;
    let umk = result.encrypted_master_key;
    let identity_keys = result.encrypted_identity_key;

    let is_password_user = umk.is_password_user();
    let auth_type = if is_password_user {
        "password"
    } else {
        "oauth"
    };

    // Build response with proper handling for OAuth vs password users
    let (encrypted_umk, umk_nonce) = match (&umk.encrypted_umk, &umk.umk_nonce) {
        (Some(enc), Some(nonce)) if !enc.is_empty() => (
            Some(base64_url::encode(enc)),
            Some(base64_url::encode(nonce)),
        ),
        _ => {
            if is_password_user {
                // Password user without encrypted_umk is a data inconsistency
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AuthErrorResponse {
                        error: "internal server error".to_string(),
                    }),
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
        encrypted_ecdh_private_nonce: base64_url::encode(
            &identity_keys.encrypted_ecdh_private_nonce,
        ),
        encrypted_signing_private: base64_url::encode(&identity_keys.encrypted_signing_private),
        encrypted_signing_private_nonce: base64_url::encode(
            &identity_keys.encrypted_signing_private_nonce,
        ),
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// PoP challenge response
#[derive(Debug, Serialize, ToSchema)]
pub struct PopChallengeResponse {
    /// Server-issued challenge (32 bytes, base64url encoded)
    #[schema(example = "base64url-encoded-challenge")]
    pub challenge: String,
    /// Challenge expiration timestamp (Unix timestamp)
    #[schema(example = 1738700000)]
    pub expires_at: i64,
}

/// Create a PoP challenge for device verification
///
/// Returns a server-issued challenge that the client must sign with
/// the device's Ed25519 signing key. The challenge is single-use and
/// expires after 5 minutes.
///
/// Requires:
/// - Valid session cookie
/// - X-PoP-Device-Id header with the device UUID
#[utoipa::path(
    post,
    path = "/api/auth/pop-challenge",
    responses(
        (status = 200, description = "Challenge created", body = PopChallengeResponse),
        (status = 400, description = "Missing or invalid device ID", body = AuthErrorResponse),
        (status = 401, description = "Not authenticated", body = AuthErrorResponse),
        (status = 404, description = "Device not found", body = AuthErrorResponse),
    ),
    tag = "auth"
)]
pub async fn create_pop_challenge<
    U,
    S,
    US,
    UIP,
    UEM,
    UEI,
    WR,
    WMR,
    WRR,
    DR,
    DUR,
    WKR,
    DKR,
    RS,
    DER,
    PDR,
    UMKR,
>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
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
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    // Authenticate session first
    let auth_user = match crate::auth::authenticate(&headers, state.session_repo().as_ref()).await {
        Ok(u) => u,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(AuthErrorResponse { error: e.error }),
            )
                .into_response();
        }
    };

    // Extract device ID from header
    let device_id_header = match headers.get(POP_DEVICE_ID_HEADER) {
        Some(h) => h,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: format!("missing {} header", POP_DEVICE_ID_HEADER),
                }),
            )
                .into_response();
        }
    };

    let device_id_str = match device_id_header.to_str() {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: format!("invalid {} header", POP_DEVICE_ID_HEADER),
                }),
            )
                .into_response();
        }
    };

    let device_uuid = match uuid::Uuid::parse_str(device_id_str) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid device ID format".to_string(),
                }),
            )
                .into_response();
        }
    };

    let device_id = DeviceId::from_uuid(device_uuid);

    // Verify device exists and belongs to user
    let device_repo = state.device_repo();
    let device = match device_repo.find_by_id(device_id).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(AuthErrorResponse {
                    error: "device not found".to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthErrorResponse {
                    error: "internal server error".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Verify device belongs to authenticated user
    if device.user_id != auth_user.user_id {
        return (
            StatusCode::NOT_FOUND,
            Json(AuthErrorResponse {
                error: "device not found".to_string(),
            }),
        )
            .into_response();
    }

    // Check device is not revoked
    if device.is_revoked() {
        return (
            StatusCode::BAD_REQUEST,
            Json(AuthErrorResponse {
                error: "device has been revoked".to_string(),
            }),
        )
            .into_response();
    }

    // Generate random 32-byte challenge
    let challenge: [u8; 32] = rand::rng().random();
    let expires_at = Utc::now() + ChronoDuration::seconds(CHALLENGE_TTL_SECS);

    // Store challenge in cache
    let challenge_store = state.challenge_store();
    if let Err(e) = challenge_store
        .store(device_id, challenge, expires_at)
        .await
    {
        tracing::error!("Failed to store PoP challenge: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuthErrorResponse {
                error: "failed to create challenge".to_string(),
            }),
        )
            .into_response();
    }

    let response = PopChallengeResponse {
        challenge: base64_url::encode(&challenge),
        expires_at: expires_at.timestamp(),
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// Recovery challenge TTL in seconds (5 minutes)
const RECOVERY_CHALLENGE_TTL_SECS: i64 = 300;

/// Recovery challenge request
#[derive(Debug, Deserialize, ToSchema)]
pub struct RecoveryChallengeRequest {
    /// User email address
    #[schema(example = "user@example.com")]
    pub email: String,
}

/// Recovery challenge response
#[derive(Debug, Serialize, ToSchema)]
pub struct RecoveryChallengeResponse {
    /// Server-issued challenge (32 bytes, base64url encoded)
    #[schema(example = "base64url-encoded-challenge")]
    pub challenge: String,
    /// Challenge expiration timestamp (Unix timestamp)
    #[schema(example = 1738700000)]
    pub expires_at: i64,
}

/// Create a recovery challenge for account recovery
///
/// Returns a server-issued challenge that must be signed with the user's
/// Identity signing key. The challenge is single-use and expires after 5 minutes.
///
/// For user enumeration prevention, always returns a challenge even for
/// non-existent users (the challenge just won't be usable).
#[utoipa::path(
    post,
    path = "/api/auth/recovery/challenge",
    request_body = RecoveryChallengeRequest,
    responses(
        (status = 200, description = "Challenge created", body = RecoveryChallengeResponse),
        (status = 400, description = "Invalid email", body = AuthErrorResponse),
    ),
    tag = "auth"
)]
pub async fn create_recovery_challenge<
    U,
    S,
    US,
    UIP,
    UEM,
    UEI,
    WR,
    WMR,
    WRR,
    DR,
    DUR,
    WKR,
    DKR,
    RS,
    DER,
    PDR,
    UMKR,
>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
    Json(request): Json<RecoveryChallengeRequest>,
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
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    // Basic email validation (just check it's not empty and has @)
    let email = request.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return (
            StatusCode::BAD_REQUEST,
            Json(AuthErrorResponse {
                error: "invalid email".to_string(),
            }),
        )
            .into_response();
    }

    // Generate random 32-byte challenge
    let challenge: [u8; 32] = rand::rng().random();
    let expires_at = Utc::now() + ChronoDuration::seconds(RECOVERY_CHALLENGE_TTL_SECS);

    // Store challenge (always succeeds, even for non-existent users)
    let recovery_challenge_store = state.recovery_challenge_store();
    if let Err(e) = recovery_challenge_store
        .store(&email, challenge, expires_at)
        .await
    {
        tracing::error!("Failed to store recovery challenge: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuthErrorResponse {
                error: "failed to create challenge".to_string(),
            }),
        )
            .into_response();
    }

    let response = RecoveryChallengeResponse {
        challenge: base64_url::encode(&challenge),
        expires_at: expires_at.timestamp(),
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// Recovery session request
#[derive(Debug, Deserialize, ToSchema)]
pub struct RecoverySessionRequest {
    /// User email address
    #[schema(example = "user@example.com")]
    pub email: String,
    /// Server-issued challenge (base64url encoded, 32 bytes)
    #[schema(example = "base64url-encoded-challenge")]
    pub challenge: String,
    /// Ed25519 signature of recovery session message (base64url encoded, 64 bytes)
    #[schema(example = "base64url-encoded-signature")]
    pub identity_signature: String,
    /// Unix timestamp (seconds) included in signed message
    #[schema(example = 1738700000)]
    pub timestamp: i64,
}

/// Recovery session response
#[derive(Debug, Serialize, ToSchema)]
pub struct RecoverySessionResponse {
    /// User ID
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub user_id: String,
    /// User email
    #[schema(example = "user@example.com")]
    pub email: String,
    /// Session expiration timestamp (ISO 8601)
    pub expires_at: String,
    /// Whether user has any registered devices
    #[schema(example = true)]
    pub has_devices: bool,
}

/// Create a recovery session using Identity signature
///
/// Authenticates the user by verifying their Identity key signature
/// over the server-issued challenge. No password required.
///
/// The client must sign: "recovery-session:" || challenge(32) || email || timestamp(8, LE)
#[utoipa::path(
    post,
    path = "/api/auth/recovery/session",
    request_body = RecoverySessionRequest,
    responses(
        (status = 200, description = "Session created. Session cookie is set.", body = RecoverySessionResponse),
        (status = 400, description = "Invalid request", body = AuthErrorResponse),
        (status = 401, description = "Invalid signature or challenge", body = AuthErrorResponse),
        (status = 500, description = "Internal server error", body = AuthErrorResponse),
    ),
    tag = "auth"
)]
pub async fn create_recovery_session<
    U,
    S,
    US,
    UIP,
    UEM,
    UEI,
    WR,
    WMR,
    WRR,
    DR,
    DUR,
    WKR,
    DKR,
    RS,
    DER,
    PDR,
    UMKR,
>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
    Json(request): Json<RecoverySessionRequest>,
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
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    // Decode base64url fields
    let challenge = match base64_url::decode(&request.challenge) {
        Ok(c) if c.len() == 32 => c,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid challenge length".to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid challenge encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let identity_signature = match base64_url::decode(&request.identity_signature) {
        Ok(s) if s.len() == ED25519_SIGNATURE_SIZE => s,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid signature length".to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: "invalid signature encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Normalize email (must match challenge creation)
    let email = request.email.trim().to_lowercase();

    // Use the application layer handler
    let handler = RecoverySessionHandler::new(
        state.user_repo(),
        state.session_repo(),
        state.user_identity_public_key_repo(),
        state.device_repo(),
        state.recovery_challenge_store(),
    );

    let command = RecoverySessionCommand {
        email,
        challenge,
        identity_signature,
        timestamp: request.timestamp,
    };

    match handler.handle(command).await {
        Ok(result) => {
            // Build HttpOnly cookie
            let cookie = build_session_cookie(
                &result.session_token,
                result.expires_at,
                false, // Recovery sessions don't use remember_me
                state.secure_cookies(),
            );

            let response = RecoverySessionResponse {
                user_id: result.user.id.to_string(),
                email: result.user.email.to_string(),
                expires_at: result.expires_at.to_rfc3339(),
                has_devices: result.has_devices,
            };

            (
                StatusCode::OK,
                AppendHeaders([(header::SET_COOKIE, cookie)]),
                Json(response),
            )
                .into_response()
        }
        Err(e) => {
            let status = if e.is_bad_request() {
                StatusCode::BAD_REQUEST
            } else if e.is_unauthorized() {
                StatusCode::UNAUTHORIZED
            } else {
                tracing::error!("recovery session error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (
                status,
                Json(AuthErrorResponse {
                    error: e.safe_message().to_string(),
                }),
            )
                .into_response()
        }
    }
}
