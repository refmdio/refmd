use application::identity::services::auth::external::ExternalAuthProviderKind;
use application::identity::services::auth::user_sessions::IssuedSessionBundle;
use axum::http::{HeaderMap, HeaderValue, header};
use chrono::{DateTime, Duration, Utc};
use rand::{Rng, distributions::Alphanumeric, rngs::OsRng};

use crate::context::AppContext;

pub(super) const SESSION_COOKIE_NAME: &str = "access_token";
const REFRESH_COOKIE_NAME: &str = "refresh_token";
pub(super) const OAUTH_STATE_COOKIE_NAME: &str = "oauth_state";
pub(super) const OAUTH_STATE_TTL_SECS: i64 = 300;

pub(super) fn generate_oauth_state() -> String {
    OsRng
        .sample_iter(&Alphanumeric)
        .take(48)
        .map(char::from)
        .collect()
}

pub(super) fn build_oauth_state_cookie(
    provider: ExternalAuthProviderKind,
    state: &str,
    secure: bool,
) -> String {
    let issued_at = Utc::now().timestamp();
    let value = format!("{}:{}:{}", provider.as_str(), state, issued_at);
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{}={}; HttpOnly{}; Path=/; Max-Age={}; SameSite=Lax",
        OAUTH_STATE_COOKIE_NAME, value, secure_attr, OAUTH_STATE_TTL_SECS
    )
}

pub(super) fn clear_oauth_state_cookie(headers: &mut HeaderMap, secure: bool) {
    let secure_attr = if secure { "; Secure" } else { "" };
    append_cookie(
        headers,
        format!(
            "{}=; HttpOnly{}; Path=/; Max-Age=0; SameSite=Lax",
            OAUTH_STATE_COOKIE_NAME, secure_attr
        ),
    );
}

pub(super) fn validate_oauth_state_cookie(
    headers: &HeaderMap,
    provider: ExternalAuthProviderKind,
    provided_state: &str,
) -> Result<(), ()> {
    let cookie_value = extract_cookie_from_headers(headers, OAUTH_STATE_COOKIE_NAME).ok_or(())?;
    let mut segments = cookie_value.splitn(3, ':');
    let provider_raw = segments.next().ok_or(())?;
    let stored_state = segments.next().ok_or(())?;
    let issued_raw = segments.next().ok_or(())?;
    let parsed_provider = ExternalAuthProviderKind::try_from(provider_raw).map_err(|_| ())?;
    if parsed_provider != provider || stored_state != provided_state {
        return Err(());
    }
    let issued_ts: i64 = issued_raw.parse().map_err(|_| ())?;
    let issued_at = DateTime::<Utc>::from_timestamp(issued_ts, 0).ok_or(())?;
    if Utc::now() - issued_at > Duration::seconds(OAUTH_STATE_TTL_SECS) {
        return Err(());
    }
    Ok(())
}

pub(super) fn get_cookie(cookie_header: &str, name: &str) -> Option<String> {
    for part in cookie_header.split(';') {
        let kv = part.trim();
        if let Some((k, v)) = kv.split_once('=') {
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn extract_cookie_from_headers(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie| get_cookie(cookie, name))
}

pub(crate) fn extract_refresh_token(headers: &HeaderMap) -> Option<String> {
    extract_cookie_from_headers(headers, REFRESH_COOKIE_NAME)
}

pub(crate) fn extract_user_agent<'a>(headers: &'a HeaderMap) -> Option<&'a str> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
}

pub(crate) fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = value.split(',').next() {
            let trimmed = first.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    headers
        .get("x-real-ip")
        .or_else(|| headers.get("cf-connecting-ip"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub(crate) fn build_session_cookie(token: &str, max_age_secs: usize, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{}={}; HttpOnly{}; Path=/; Max-Age={}; SameSite=Lax",
        SESSION_COOKIE_NAME, token, secure_attr, max_age_secs
    )
}

fn build_refresh_cookie(token: &str, max_age_secs: usize, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{}={}; HttpOnly{}; Path=/; Max-Age={}; SameSite=Lax",
        REFRESH_COOKIE_NAME, token, secure_attr, max_age_secs
    )
}

fn clear_session_cookie(secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{}=; HttpOnly{}; Path=/; Max-Age=0; SameSite=Lax",
        SESSION_COOKIE_NAME, secure_attr
    )
}

fn clear_refresh_cookie(secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{}=; HttpOnly{}; Path=/; Max-Age=0; SameSite=Lax",
        REFRESH_COOKIE_NAME, secure_attr
    )
}

pub(super) fn append_cookie(headers: &mut HeaderMap, value: String) {
    if let Ok(header_value) = HeaderValue::from_str(&value) {
        headers.append(header::SET_COOKIE, header_value);
    }
}

fn refresh_cookie_max_age(expires_at: DateTime<Utc>) -> usize {
    let now = Utc::now();
    if expires_at <= now {
        0
    } else {
        (expires_at - now).num_seconds().max(0) as usize
    }
}

pub(crate) fn apply_session_cookies(
    ctx: &AppContext,
    headers: &mut HeaderMap,
    issued: &IssuedSessionBundle,
) {
    append_cookie(
        headers,
        build_session_cookie(
            &issued.access.token,
            ctx.auth_service().session_ttl_secs(),
            ctx.cfg.session_cookie_secure,
        ),
    );
    append_cookie(
        headers,
        build_refresh_cookie(
            &issued.refresh_token,
            refresh_cookie_max_age(issued.refresh_expires_at),
            ctx.cfg.session_cookie_secure,
        ),
    );
}

pub(crate) fn clear_auth_cookies(headers: &mut HeaderMap, secure: bool) {
    append_cookie(headers, clear_session_cookie(secure));
    append_cookie(headers, clear_refresh_cookie(secure));
}
