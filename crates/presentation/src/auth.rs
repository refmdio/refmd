//! Authentication extractors and middleware
//!
//! Provides authentication helpers for authenticated requests.

use application::domain::document::{DocumentRepository, DocumentUpdateRepository};
use application::domain::encryption::{
    Device, DeviceEncryptedUMKRepository, DeviceId, DeviceRepository,
    DocumentEncryptedKeyRepository, PendingDeviceRepository, UserEncryptedIdentityKeyRepository,
    UserEncryptedMasterKeyRepository, UserIdentityPublicKeyRepository,
    WorkspaceEncryptedKeyRepository,
};
use application::domain::identity::{
    Session, SessionRepository, User, UserId, UserRepository, UserSettingsRepository,
};
use application::domain::workspace::{
    WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRoleRepository,
};
use application::identity::RegistrationService;
use axum::{
    Json,
    extract::FromRequestParts,
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::{
    AppState,
    middleware::{
        ChallengeError, ChallengeStore, POP_CHALLENGE_HEADER, POP_DEVICE_ID_HEADER,
        POP_SIGNATURE_HEADER,
    },
    routes::auth::SESSION_COOKIE_NAME,
};

/// Authenticated user information extracted from session
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: UserId,
    pub session: Session,
}

/// Authenticated user with full user data
#[derive(Debug, Clone)]
pub struct AuthUserFull<
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
> where
    U: UserRepository + Send + Sync + 'static,
    S: SessionRepository + Send + Sync + 'static,
    US: UserSettingsRepository + Send + Sync + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + 'static,
    WR: WorkspaceRepository + Send + Sync + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + 'static,
    DR: DocumentRepository + Send + Sync + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + 'static,
    RS: RegistrationService + Send + Sync + 'static,
    DER: DeviceRepository + Send + Sync + 'static,
    PDR: PendingDeviceRepository + Send + Sync + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + 'static,
{
    pub user: User,
    pub session: Session,
    #[doc(hidden)]
    _phantom: std::marker::PhantomData<(
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
    )>,
}

impl<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>
    FromRequestParts<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    > for AuthUserFull<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>
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
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState<
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
    ) -> Result<Self, Self::Rejection> {
        let token = extract_session_token(&parts.headers)?;
        let token_hash = hash_session_token(token);

        let session_repo = state.session_repo();
        let session = session_repo
            .find_by_token_hash(&token_hash)
            .await
            .map_err(|_| AuthError::internal_error())?
            .ok_or_else(AuthError::invalid_session)?;

        if session.is_expired() {
            return Err(AuthError::expired_session());
        }

        let user_repo = state.user_repo();
        let user = user_repo
            .find_by_id(session.user_id)
            .await
            .map_err(|_| AuthError::internal_error())?
            .ok_or_else(AuthError::user_not_found)?;

        Ok(AuthUserFull {
            user,
            session,
            _phantom: std::marker::PhantomData,
        })
    }
}

/// Authentication error response
#[derive(Debug, Serialize)]
pub struct AuthError {
    pub error: String,
}

impl AuthError {
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
        }
    }

    pub fn missing_session() -> Self {
        Self::new("missing session cookie")
    }

    pub fn invalid_session() -> Self {
        Self::new("invalid session")
    }

    pub fn expired_session() -> Self {
        Self::new("session expired")
    }

    pub fn user_not_found() -> Self {
        Self::new("user not found")
    }

    pub fn internal_error() -> Self {
        Self::new("internal server error")
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, Json(self)).into_response()
    }
}

/// Extract session token from cookie
pub fn extract_session_token(headers: &HeaderMap) -> Result<&str, AuthError> {
    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(AuthError::missing_session)?;

    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix(&format!("{}=", SESSION_COOKIE_NAME))
            && !value.is_empty()
        {
            return Ok(value);
        }
    }

    Err(AuthError::missing_session())
}

/// Authenticate request using session repository
///
/// This function validates the session token from the HttpOnly cookie
/// and returns the authenticated user information.
pub async fn authenticate<S: SessionRepository>(
    headers: &HeaderMap,
    session_repo: &S,
) -> Result<AuthUser, AuthError> {
    let token = extract_session_token(headers)?;
    let token_hash = hash_session_token(token);

    let session = session_repo
        .find_by_token_hash(&token_hash)
        .await
        .map_err(|_| AuthError::internal_error())?
        .ok_or_else(AuthError::invalid_session)?;

    if session.is_expired() {
        return Err(AuthError::expired_session());
    }

    Ok(AuthUser {
        user_id: session.user_id,
        session,
    })
}

/// Authenticate request and load full user data
pub async fn authenticate_full<S: SessionRepository, U: UserRepository>(
    headers: &HeaderMap,
    session_repo: &S,
    user_repo: &U,
) -> Result<(User, Session), AuthError> {
    let auth_user = authenticate(headers, session_repo).await?;

    let user = user_repo
        .find_by_id(auth_user.user_id)
        .await
        .map_err(|_| AuthError::internal_error())?
        .ok_or_else(AuthError::user_not_found)?;

    Ok((user, auth_user.session))
}

/// PoP (Proof of Possession) verification error
#[derive(Debug, Serialize)]
pub struct PopError {
    pub error: String,
}

impl PopError {
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
        }
    }

    pub fn missing_header(name: &str) -> Self {
        Self::new(format!("missing {} header", name))
    }

    pub fn invalid_header(name: &str) -> Self {
        Self::new(format!("invalid {} header", name))
    }

    pub fn challenge_not_found() -> Self {
        Self::new("challenge not found or already used")
    }

    pub fn challenge_expired() -> Self {
        Self::new("challenge has expired")
    }

    pub fn device_not_found() -> Self {
        Self::new("device not found")
    }

    pub fn device_revoked() -> Self {
        Self::new("device has been revoked")
    }

    pub fn device_user_mismatch() -> Self {
        Self::new("device does not belong to user")
    }

    pub fn invalid_signature() -> Self {
        Self::new("invalid signature")
    }

    pub fn internal_error() -> Self {
        Self::new("internal server error")
    }
}

impl IntoResponse for PopError {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, Json(self)).into_response()
    }
}

/// Verified PoP result containing the device
#[derive(Debug)]
pub struct PopVerified {
    pub device: Device,
}

/// Verify PoP (Proof of Possession) headers with server-issued challenge
///
/// This function validates the PoP headers to ensure the request comes from
/// a legitimate device. It checks:
/// 1. All required headers are present
/// 2. The challenge was issued by the server and hasn't been used (one-time use)
/// 3. The challenge hasn't expired
/// 4. The device exists and belongs to the authenticated user
/// 5. The signature is valid
///
/// Returns the verified device on success.
pub async fn verify_pop<D: DeviceRepository>(
    headers: &HeaderMap,
    user_id: UserId,
    device_repo: &D,
    challenge_store: &Arc<dyn ChallengeStore>,
) -> Result<PopVerified, PopError> {
    // Extract X-PoP-Challenge (server-issued)
    let challenge_header = headers
        .get(POP_CHALLENGE_HEADER)
        .ok_or_else(|| PopError::missing_header(POP_CHALLENGE_HEADER))?;
    let challenge_str = challenge_header
        .to_str()
        .map_err(|_| PopError::invalid_header(POP_CHALLENGE_HEADER))?;
    let challenge = base64_url::decode(challenge_str)
        .map_err(|_| PopError::invalid_header(POP_CHALLENGE_HEADER))?;
    if challenge.len() != 32 {
        return Err(PopError::new("challenge must be 32 bytes"));
    }
    let challenge_bytes: [u8; 32] = challenge
        .try_into()
        .map_err(|_| PopError::invalid_header(POP_CHALLENGE_HEADER))?;

    // Extract X-PoP-Signature
    let sig_header = headers
        .get(POP_SIGNATURE_HEADER)
        .ok_or_else(|| PopError::missing_header(POP_SIGNATURE_HEADER))?;
    let sig_str = sig_header
        .to_str()
        .map_err(|_| PopError::invalid_header(POP_SIGNATURE_HEADER))?;
    let signature =
        base64_url::decode(sig_str).map_err(|_| PopError::invalid_header(POP_SIGNATURE_HEADER))?;
    if signature.len() != 64 {
        return Err(PopError::new("signature must be 64 bytes"));
    }

    // Extract X-PoP-Device-Id
    let device_id_header = headers
        .get(POP_DEVICE_ID_HEADER)
        .ok_or_else(|| PopError::missing_header(POP_DEVICE_ID_HEADER))?;
    let device_id_str = device_id_header
        .to_str()
        .map_err(|_| PopError::invalid_header(POP_DEVICE_ID_HEADER))?;
    let device_uuid = uuid::Uuid::parse_str(device_id_str)
        .map_err(|_| PopError::invalid_header(POP_DEVICE_ID_HEADER))?;
    let device_id = DeviceId::from_uuid(device_uuid);

    // Fetch device first (before consuming challenge)
    let device = device_repo
        .find_by_id(device_id)
        .await
        .map_err(|_| PopError::internal_error())?
        .ok_or_else(PopError::device_not_found)?;

    // Check device belongs to authenticated user
    if device.user_id != user_id {
        return Err(PopError::device_user_mismatch());
    }

    // Check device is not revoked
    if device.is_revoked() {
        return Err(PopError::device_revoked());
    }

    // Verify Ed25519 signature over the challenge
    let pk_bytes: [u8; 32] = device
        .signing_public_key
        .as_slice()
        .try_into()
        .map_err(|_| PopError::internal_error())?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| PopError::internal_error())?;
    let sig_bytes: [u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| PopError::invalid_signature())?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    use ed25519_dalek::Verifier;
    verifying_key
        .verify(&challenge_bytes, &sig)
        .map_err(|_| PopError::invalid_signature())?;

    // Signature verified successfully - atomically verify and consume the challenge
    // GETDEL ensures no TOCTOU race condition for single-use challenges
    challenge_store
        .verify_and_remove(device_id, &challenge_bytes)
        .await
        .map_err(|e| match e {
            ChallengeError::NotFound => PopError::challenge_not_found(),
            ChallengeError::Expired => PopError::challenge_expired(),
            ChallengeError::StoreError => PopError::internal_error(),
        })?;

    Ok(PopVerified { device })
}

/// Authenticate with PoP verification combined
///
/// This is a convenience function that performs both session authentication
/// and PoP verification in one call. Returns the authenticated user info
/// along with the verified device.
pub async fn authenticate_with_pop<S: SessionRepository, D: DeviceRepository>(
    headers: &HeaderMap,
    session_repo: &S,
    device_repo: &D,
    challenge_store: &Arc<dyn ChallengeStore>,
) -> Result<(AuthUser, PopVerified), Response> {
    // First, authenticate the session
    let auth_user = authenticate(headers, session_repo)
        .await
        .map_err(|e| e.into_response())?;

    // Then, verify PoP
    let pop_verified = verify_pop(headers, auth_user.user_id, device_repo, challenge_store)
        .await
        .map_err(|e| e.into_response())?;

    Ok((auth_user, pop_verified))
}

/// Hash session token for storage/lookup
pub fn hash_session_token(token: &str) -> String {
    let hash = Sha256::digest(token.as_bytes());
    let mut hex = String::with_capacity(64);
    for b in hash {
        std::fmt::Write::write_fmt(&mut hex, format_args!("{:02x}", b))
            .expect("Failed to write hex");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_session_token() {
        let token = "test-token-123";
        let hash = hash_session_token(token);

        // Hash should be 64 hex characters (32 bytes)
        assert_eq!(hash.len(), 64);

        // Same token should produce same hash
        assert_eq!(hash, hash_session_token(token));

        // Different token should produce different hash
        assert_ne!(hash, hash_session_token("different-token"));
    }

    #[test]
    fn test_extract_session_token() {
        use axum::http::HeaderValue;

        let mut headers = HeaderMap::new();

        // Missing cookie header
        assert!(extract_session_token(&headers).is_err());

        // Cookie header without session cookie
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other_cookie=value"),
        );
        assert!(extract_session_token(&headers).is_err());

        // Valid session cookie
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("refmd_session=my-token; other=value"),
        );
        assert_eq!(extract_session_token(&headers).unwrap(), "my-token");

        // Session cookie only
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("refmd_session=token123"),
        );
        assert_eq!(extract_session_token(&headers).unwrap(), "token123");
    }
}
