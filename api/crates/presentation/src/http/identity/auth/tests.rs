use axum::http::{HeaderMap, HeaderValue, header};
use chrono::Utc;

use super::cookies::{OAUTH_STATE_COOKIE_NAME, OAUTH_STATE_TTL_SECS, validate_oauth_state_cookie};
use application::identity::services::auth::external::ExternalAuthProviderKind;

fn cookie_headers(provider: ExternalAuthProviderKind, state: &str, issued_at: i64) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let raw_value = format!(
        "{}={}:{}:{}",
        OAUTH_STATE_COOKIE_NAME,
        provider.as_str(),
        state,
        issued_at
    );
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&raw_value).expect("header"),
    );
    headers
}

#[test]
fn oauth_state_cookie_roundtrip() {
    let provider = ExternalAuthProviderKind::Github;
    let state = "state-token";
    let issued = Utc::now().timestamp();
    let headers = cookie_headers(provider, state, issued);
    assert!(validate_oauth_state_cookie(&headers, provider, state).is_ok());
}

#[test]
fn oauth_state_cookie_rejects_expired() {
    let provider = ExternalAuthProviderKind::Github;
    let state = "expired";
    let issued = Utc::now().timestamp() - (OAUTH_STATE_TTL_SECS + 10);
    let headers = cookie_headers(provider, state, issued);
    assert!(validate_oauth_state_cookie(&headers, provider, state).is_err());
}
