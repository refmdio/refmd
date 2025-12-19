use std::sync::Arc;

use application::core::services::access;
use application::core::services::errors::ServiceError;
use application::identity::services::auth::user_sessions::{IssuedSessionBundle, SessionMetadata};
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    middleware::Next,
    response::IntoResponse,
};

use crate::context::AppContext;
use crate::http::error::ApiError;
use crate::security::token::{AccessTokenOverride, Bearer};

use super::cookies::{
    SESSION_COOKIE_NAME, apply_session_cookies, clear_auth_cookies, extract_client_ip,
    extract_refresh_token, extract_user_agent, get_cookie,
};
use super::request_status;

#[derive(Clone)]
pub struct RefreshedSession(pub Arc<IssuedSessionBundle>);

fn unauthorized_token_expired(ctx: &AppContext) -> axum::response::Response {
    let mut headers = HeaderMap::new();
    clear_auth_cookies(&mut headers, ctx.cfg.session_cookie_secure);
    let _ = headers.insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer error=\"token_expired\""),
    );
    (headers, StatusCode::UNAUTHORIZED).into_response()
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    if let Some(cookie) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = get_cookie(cookie, SESSION_COOKIE_NAME) {
            if !token.trim().is_empty() {
                return Some(token);
            }
        }
    }

    if let Some(auth) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(t) = auth.strip_prefix("Bearer ") {
            let trimmed = t.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn should_skip_refresh(path: &str) -> bool {
    path.starts_with("/api/public") || path.starts_with("/api/health") || path == "/metrics"
}

pub(crate) async fn validate_bearer(ctx: &AppContext, bearer: Bearer) -> Result<String, ApiError> {
    validate_bearer_str(ctx, &bearer.0).await
}

pub async fn validate_bearer_public(ctx: &AppContext, bearer: Bearer) -> Result<String, ApiError> {
    validate_bearer(ctx, bearer).await
}

pub async fn validate_bearer_str(ctx: &AppContext, token: &str) -> Result<String, ApiError> {
    let service = ctx.auth_service();
    let session_service = ctx.session_service();
    let subject = match service.subject_from_token(token).await {
        Ok(Some(sub)) => sub,
        Ok(None) => return Err(ApiError::unauthorized("unauthorized")),
        Err(ServiceError::TokenExpired) => {
            request_status::mark_token_expired();
            return Err(ApiError::unauthorized("token_expired"));
        }
        Err(err) => return Err(map_auth_error(err)),
    };
    if let Some(session_id) = service.session_id_from_token_claim(token) {
        session_service
            .ensure_session_active(session_id)
            .await
            .map_err(map_auth_error)?;
    }
    Ok(subject)
}

pub async fn resolve_actor_from_parts(
    ctx: &AppContext,
    bearer: Option<Bearer>,
    share_token: Option<&str>,
) -> Option<access::Actor> {
    crate::security::token::resolve_actor_from_parts(ctx, bearer, share_token)
        .await
        .ok()
        .flatten()
}

pub async fn refresh_middleware(
    State(ctx): State<AppContext>,
    mut req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    let path = req.uri().path().to_owned();
    if should_skip_refresh(&path) {
        return next.run(req).await;
    }

    let mut refreshed: Option<Arc<IssuedSessionBundle>> = None;
    let force_refresh = path == "/api/auth/refresh";
    let access_token = extract_bearer_token(req.headers());
    let refresh_token = extract_refresh_token(req.headers());

    if force_refresh || access_token.is_some() || refresh_token.is_some() {
        let auth = ctx.auth_service();
        let session_service = ctx.session_service();

        let token_expired_or_missing = if force_refresh {
            true
        } else if let Some(access_token) = access_token {
            match auth.subject_from_token(&access_token).await {
                Ok(Some(_)) => false,
                Ok(None) => false,
                Err(ServiceError::TokenExpired) => true,
                Err(_) => false,
            }
        } else if refresh_token.is_some() {
            true
        } else {
            false
        };

        if token_expired_or_missing {
            if let Some(refresh_token) = refresh_token {
                let client_ip = extract_client_ip(req.headers());
                let meta = SessionMetadata {
                    user_agent: extract_user_agent(req.headers()),
                    ip_address: client_ip.as_deref(),
                };
                match session_service
                    .refresh_session(&refresh_token, None, meta)
                    .await
                {
                    Ok(bundle) => {
                        let shared = Arc::new(bundle);
                        req.extensions_mut()
                            .insert(AccessTokenOverride(shared.access.token.clone()));
                        req.extensions_mut()
                            .insert(RefreshedSession(shared.clone()));
                        refreshed = Some(shared);
                    }
                    Err(ServiceError::Unauthorized) => return unauthorized_token_expired(&ctx),
                    Err(err) => return map_auth_error(err).into_response(),
                }
            } else {
                return unauthorized_token_expired(&ctx);
            }
        }
    }

    let mut response = next.run(req).await;
    if let Some(bundle) = refreshed {
        apply_session_cookies(&ctx, response.headers_mut(), bundle.as_ref());
    }
    response
}

pub async fn resolve_actor_from_token_str(ctx: &AppContext, token: &str) -> Option<access::Actor> {
    crate::security::token::resolve_actor_from_token_str(ctx, token)
        .await
        .ok()
}

pub(crate) fn map_auth_error(err: ServiceError) -> ApiError {
    match err {
        ServiceError::Unauthorized => ApiError::unauthorized("unauthorized"),
        ServiceError::TokenExpired => ApiError::unauthorized("token_expired"),
        ServiceError::Forbidden => ApiError::forbidden("forbidden"),
        ServiceError::NotFound => ApiError::not_found("not_found"),
        ServiceError::Conflict => ApiError::conflict("conflict"),
        ServiceError::BadRequest(code) => ApiError::bad_request(code).with_message(code),
        ServiceError::Unexpected(_) => {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        }
    }
}
