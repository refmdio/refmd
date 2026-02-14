//! Proof-of-Possession (PoP) verification extractors and helpers

use application::dto::{DeviceDto, SessionDto};
use application::types::{DeviceId, UserId};
use application::encryption::{
    VerifyPopAndBindError, VerifyPopAndBindHandler, VerifyPopCommand, VerifyPopError,
};
use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, StatusCode, request::Parts},
    response::{IntoResponse, Response},
};

use crate::AppState;

/// PoP header names
pub const POP_CHALLENGE_HEADER: &str = "X-PoP-Challenge";
pub const POP_SIGNATURE_HEADER: &str = "X-PoP-Signature";
pub const POP_DEVICE_ID_HEADER: &str = "X-PoP-Device-Id";
use super::session::{AuthError, authenticate};

/// Parsed PoP headers: (challenge_str, challenge_bytes, signature_bytes, device_id, device_id_str)
type PopHeaders = (String, [u8; 32], [u8; 64], DeviceId, String);

/// Convert a `(StatusCode, String)` validation error into an `AuthError`.
fn pop_validation_err((_status, msg): (StatusCode, String)) -> AuthError {
    AuthError::new(msg)
}

/// Extract a required header value as a `&str`, returning an `AuthError` on failure.
pub(crate) fn require_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, AuthError> {
    headers
        .get(name)
        .ok_or_else(|| AuthError::missing_header(name))?
        .to_str()
        .map_err(|_| AuthError::invalid_header(name))
}

/// Extract PoP headers from the request and parse them into domain types.
fn extract_pop_headers(headers: &HeaderMap) -> Result<PopHeaders, AuthError> {
    use crate::crypto_validation::{decode_b64_array, parse_device_id};

    let challenge_str = require_header(headers, POP_CHALLENGE_HEADER)?;
    let challenge_bytes: [u8; 32] =
        decode_b64_array::<32>(POP_CHALLENGE_HEADER, challenge_str).map_err(pop_validation_err)?;

    let sig_str = require_header(headers, POP_SIGNATURE_HEADER)?;
    let signature_bytes: [u8; 64] =
        decode_b64_array::<64>(POP_SIGNATURE_HEADER, sig_str).map_err(pop_validation_err)?;

    let device_id_str = require_header(headers, POP_DEVICE_ID_HEADER)?;
    let device_id =
        parse_device_id(POP_DEVICE_ID_HEADER, device_id_str).map_err(pop_validation_err)?;

    Ok((challenge_str.to_string(), challenge_bytes, signature_bytes, device_id, device_id_str.to_string()))
}

/// Map application-layer VerifyPopError to presentation-layer AuthError.
fn map_verify_pop_error<E: std::error::Error>(e: VerifyPopError<E>) -> AuthError {
    match e {
        VerifyPopError::Unauthorized => AuthError::unauthorized(),
        VerifyPopError::DeviceRevoked => AuthError::device_revoked(),
        VerifyPopError::InvalidSignature => AuthError::invalid_signature(),
        VerifyPopError::ChallengeNotFound => AuthError::challenge_not_found(),
        VerifyPopError::ChallengeExpired => AuthError::challenge_expired(),
        VerifyPopError::Internal(_) | VerifyPopError::DeviceRepository(_) => {
            AuthError::internal_error()
        }
    }
}

/// Map application-layer VerifyPopAndBindError to presentation-layer AuthError.
fn map_verify_pop_and_bind_error<DR: std::error::Error>(
    e: VerifyPopAndBindError<DR>,
) -> AuthError {
    match e {
        VerifyPopAndBindError::Pop(pop_err) => map_verify_pop_error(pop_err),
        VerifyPopAndBindError::BindFailed(_) => AuthError::internal_error(),
    }
}

/// Verify PoP and auto-bind device_id to session if not yet set.
///
/// Shared by `PopVerifiedUser` and `RecoveryOrPopUser` extractors.
/// Delegates to the application-layer `VerifyPopAndBindHandler`.
async fn verify_pop_and_bind_session(
    headers: &HeaderMap,
    session: SessionDto,
    state: &AppState,
) -> Result<(SessionDto, DeviceDto), Response> {
    let (challenge_str, challenge_bytes, signature_bytes, device_id, device_id_str) =
        extract_pop_headers(headers).map_err(|e| e.into_response())?;

    let handler = VerifyPopAndBindHandler::new(
        state.device_repo(),
        state.session_repo(),
        state.challenge_store(),
    );

    let command = VerifyPopCommand {
        user_id: session.user_id,
        device_id,
        challenge_str,
        challenge_bytes,
        signature_bytes,
        device_id_str,
    };

    let result = handler
        .handle(command, session)
        .await
        .map_err(|e| map_verify_pop_and_bind_error(e).into_response())?;

    Ok((result.session, result.device))
}

/// PoP-verified user - combines session authentication with PoP verification.
///
/// Use this extractor for routes that require both session auth and PoP.
/// The verified device is available on the extracted struct.
#[derive(Debug)]
pub struct PopVerifiedUser {
    pub user_id: UserId,
    pub session: SessionDto,
    pub device: DeviceDto,
}

impl FromRequestParts<AppState> for PopVerifiedUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = authenticate(&parts.headers, state)
            .await
            .map_err(|e| e.into_response())?;

        let (session, device) =
            verify_pop_and_bind_session(&parts.headers, auth.session, state).await?;

        Ok(PopVerifiedUser {
            user_id: auth.user_id,
            session,
            device,
        })
    }
}

/// Recovery-or-PoP verified user - combines session auth with conditional PoP verification.
///
/// For recovery sessions (is_recovery = true), PoP verification is skipped because
/// recovery sessions lack a registered device to sign challenges with.
/// For normal sessions, PoP verification is required.
#[derive(Debug)]
pub struct RecoveryOrPopUser {
    pub user_id: UserId,
    pub session: SessionDto,
    /// The verified device. None if this is a recovery session.
    pub device: Option<DeviceDto>,
}

impl FromRequestParts<AppState> for RecoveryOrPopUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = authenticate(&parts.headers, state)
            .await
            .map_err(|e| e.into_response())?;

        let (session, device) = if auth.session.is_recovery {
            (auth.session, None)
        } else {
            let (session, device) =
                verify_pop_and_bind_session(&parts.headers, auth.session, state).await?;
            (session, Some(device))
        };

        Ok(RecoveryOrPopUser {
            user_id: auth.user_id,
            session,
            device,
        })
    }
}
