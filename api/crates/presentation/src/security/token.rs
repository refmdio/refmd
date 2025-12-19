use application::core::services::{access, errors::ServiceError};
use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use axum::http::request::Parts;
use tracing::error;
use uuid::Uuid;

use crate::context::HasAuthServices;
use crate::http::error::ApiError;
use crate::security::request_status;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorResolveError {
    TokenExpired,
    Unauthorized,
}

#[derive(Debug, Clone)]
pub struct Bearer(pub String);

#[derive(Debug, Clone)]
pub struct AccessTokenOverride(pub String);

fn get_cookie(cookie_header: &str, name: &str) -> Option<String> {
    for part in cookie_header.split(';') {
        let kv = part.trim();
        if let Some((k, v)) = kv.split_once('=')
            && k.trim() == name
        {
            return Some(v.trim().to_string());
        }
    }
    None
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    // Prefer the session cookie if present to avoid accidentally overriding it
    // with other Bearer values (e.g. share tokens) that might be sent by the
    // client.
    if let Some(cookie) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        && let Some(token) = get_cookie(cookie, "access_token")
        && !token.trim().is_empty()
    {
        return Some(token);
    }

    if let Some(auth) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        && let Some(t) = auth.strip_prefix("Bearer ")
        && let trimmed = t.trim()
        && !trimmed.is_empty()
    {
        return Some(trimmed.to_string());
    }
    None
}

pub fn bearer_from_headers(headers: &HeaderMap) -> Option<Bearer> {
    extract_bearer_token(headers).map(Bearer)
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for Bearer
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(token) = parts.extensions.get::<AccessTokenOverride>() {
            return Ok(Bearer(token.0.clone()));
        }
        extract_bearer_token(&parts.headers)
            .map(Bearer)
            .ok_or(ApiError::unauthorized("unauthorized"))
    }
}

pub fn map_actor_error(err: ActorResolveError) -> ApiError {
    match err {
        ActorResolveError::TokenExpired => ApiError::unauthorized("token_expired"),
        ActorResolveError::Unauthorized => ApiError::unauthorized("unauthorized"),
    }
}

pub async fn resolve_actor_from_token_str(
    ctx: &impl HasAuthServices,
    token: &str,
) -> Result<access::Actor, ActorResolveError> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Err(ActorResolveError::Unauthorized);
    }

    let service = ctx.auth_service();
    match service.subject_from_token(trimmed).await {
        Ok(Some(sub)) => {
            if let Ok(uid) = Uuid::parse_str(&sub) {
                if let Some(session_id) = service.session_id_from_token_claim(trimmed)
                    && let Err(err) = ctx
                        .session_service()
                        .ensure_session_active(session_id)
                        .await
                {
                    if err.is_internal() {
                        error!(error = ?err, "session_validation_failed");
                    }
                    return Err(ActorResolveError::Unauthorized);
                }
                Ok(access::Actor::User(uid))
            } else {
                Ok(access::Actor::Public)
            }
        }
        Ok(None) => Ok(access::Actor::ShareToken(trimmed.to_string())),
        Err(ServiceError::TokenExpired) => {
            request_status::mark_token_expired();
            Err(ActorResolveError::TokenExpired)
        }
        Err(err) => {
            if err.is_internal() {
                error!(error = ?err, "token_validation_failed");
            }
            Err(ActorResolveError::Unauthorized)
        }
    }
}

pub async fn resolve_actor_from_parts(
    ctx: &impl HasAuthServices,
    bearer: Option<Bearer>,
    share_token: Option<&str>,
) -> Result<Option<access::Actor>, ActorResolveError> {
    if let Some(token) = share_token
        && let Ok(actor) = resolve_actor_from_token_str(ctx, token).await
    {
        return Ok(Some(actor));
    }

    if let Some(b) = bearer
        && let Ok(actor) = resolve_actor_from_token_str(ctx, &b.0).await
    {
        return Ok(Some(actor));
    }

    Ok(None)
}

pub async fn require_user_id(
    ctx: &impl HasAuthServices,
    bearer: Bearer,
) -> Result<Uuid, ActorResolveError> {
    match resolve_actor_from_token_str(ctx, &bearer.0).await? {
        access::Actor::User(user_id) => Ok(user_id),
        _ => Err(ActorResolveError::Unauthorized),
    }
}
