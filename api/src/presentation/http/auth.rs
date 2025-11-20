use crate::application::access;
use crate::application::dto::auth::UserDto;
use crate::application::ports::user_session_repository::UserSessionRecord;
use crate::application::ports::workspace_repository::WorkspaceListItem;
use crate::application::services::auth::external::{ExternalAuthPayload, ExternalAuthProviderKind};
use crate::application::services::auth::user_sessions::{IssuedSessionBundle, SessionMetadata};
use crate::application::services::errors::ServiceError;
use crate::presentation::context::AppContext;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    routing::{delete, get, post},
};
use chrono::{DateTime, Duration, Utc};
use rand::{Rng, distributions::Alphanumeric, rngs::OsRng};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::presentation::http::workspace_scope;

const SESSION_COOKIE_NAME: &str = "access_token";
const REFRESH_COOKIE_NAME: &str = "refresh_token";
const OAUTH_STATE_COOKIE_NAME: &str = "oauth_state";
const OAUTH_STATE_TTL_SECS: i64 = 300;

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub email: String,
    pub name: String,
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub workspaces: Vec<WorkspaceMembershipResponse>,
    pub active_workspace_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_workspace: Option<WorkspaceMembershipResponse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_workspace_permissions: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionResponse {
    pub id: Uuid,
    pub workspace_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    pub remember_me: bool,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub current: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RefreshResponse {
    pub access_token: String,
}

#[derive(Debug, Serialize, ToSchema, Clone)]
pub struct WorkspaceMembershipResponse {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub is_personal: bool,
    pub role_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_role_id: Option<Uuid>,
    pub is_default: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub remember_me: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    pub access_token: String,
    pub user: UserResponse,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct OAuthLoginRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub remember_me: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OAuthStateResponse {
    pub state: String,
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/oauth/:provider/state", post(oauth_state))
        .route("/oauth/:provider", post(oauth_login))
        .route("/logout", post(logout))
        .route("/refresh", post(refresh_session))
        .route("/sessions", get(list_sessions))
        .route("/sessions/:id", delete(revoke_session))
        .route("/me", get(me).delete(delete_account))
        .with_state(ctx)
}

#[utoipa::path(
    post,
    path = "/api/auth/oauth/{provider}/state",
    tag = "Auth",
    params(("provider" = String, Path, description = "OAuth provider identifier")),
    security(()),
    responses((status = 200, body = OAuthStateResponse))
)]
pub async fn oauth_state(
    Path(provider): Path<String>,
    State(ctx): State<AppContext>,
) -> Result<(HeaderMap, Json<OAuthStateResponse>), StatusCode> {
    let provider_kind =
        ExternalAuthProviderKind::try_from(provider.as_str()).map_err(|_| StatusCode::NOT_FOUND)?;
    if ctx.external_auth().get(provider_kind).is_none() {
        return Err(StatusCode::NOT_IMPLEMENTED);
    }
    let state = generate_oauth_state();
    let mut headers = HeaderMap::new();
    append_cookie(
        &mut headers,
        build_oauth_state_cookie(provider_kind, &state, ctx.cfg.session_cookie_secure),
    );
    Ok((headers, Json(OAuthStateResponse { state })))
}

#[utoipa::path(
    post,
    path = "/api/auth/oauth/{provider}",
    tag = "Auth",
    params(
        ("provider" = String, Path, description = "OAuth provider identifier (e.g., google)")
    ),
    request_body = OAuthLoginRequest,
    security(()),
    responses((status = 200, body = LoginResponse))
)]
pub async fn oauth_login(
    Path(provider): Path<String>,
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Json(req): Json<OAuthLoginRequest>,
) -> Result<(HeaderMap, Json<LoginResponse>), StatusCode> {
    let provider_kind =
        ExternalAuthProviderKind::try_from(provider.as_str()).map_err(|_| StatusCode::NOT_FOUND)?;
    let registry = ctx.external_auth();
    let verifier = registry
        .get(provider_kind)
        .ok_or(StatusCode::NOT_IMPLEMENTED)?;
    let mut response_headers = HeaderMap::new();
    if provider_kind.requires_state() {
        let provided_state = req.state.as_deref().ok_or(StatusCode::BAD_REQUEST)?;
        validate_oauth_state_cookie(&headers, provider_kind, provided_state)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        clear_oauth_state_cookie(&mut response_headers, ctx.cfg.session_cookie_secure);
    }
    let payload = ExternalAuthPayload {
        credential: req.credential.clone(),
        code: req.code.clone(),
        redirect_uri: req.redirect_uri.clone(),
    };
    let identity = verifier.verify(&payload).await.map_err(map_auth_error)?;
    let account_service = ctx.account_service();
    let user_dto = account_service
        .sign_in_with_external(identity)
        .await
        .map_err(map_account_error)?;
    let user = build_user_response(&ctx, user_dto, None).await?;
    let active_workspace_id = user
        .active_workspace_id
        .or_else(|| user.workspaces.iter().find(|w| w.is_default).map(|w| w.id))
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let client_ip = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);
    let issued = ctx
        .session_service()
        .issue_new_session(
            user.id,
            active_workspace_id,
            req.remember_me,
            SessionMetadata {
                user_agent,
                ip_address: client_ip.as_deref(),
            },
        )
        .await
        .map_err(map_auth_error)?;
    apply_session_cookies(&ctx, &mut response_headers, &issued);
    Ok((
        response_headers,
        Json(LoginResponse {
            access_token: issued.access.token,
            user,
        }),
    ))
}

fn map_account_error(err: ServiceError) -> StatusCode {
    match err {
        ServiceError::Unauthorized => StatusCode::UNAUTHORIZED,
        ServiceError::Forbidden => StatusCode::FORBIDDEN,
        ServiceError::Conflict => StatusCode::CONFLICT,
        ServiceError::NotFound => StatusCode::NOT_FOUND,
        ServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
        ServiceError::Unexpected(inner) => {
            error!(error = ?inner, "account_service_error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

fn map_workspace_error(err: ServiceError) -> StatusCode {
    match err {
        ServiceError::Unauthorized => StatusCode::UNAUTHORIZED,
        ServiceError::Forbidden => StatusCode::FORBIDDEN,
        ServiceError::Conflict => StatusCode::CONFLICT,
        ServiceError::NotFound => StatusCode::NOT_FOUND,
        ServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
        ServiceError::Unexpected(inner) => {
            error!(error = ?inner, "workspace_service_error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

fn workspace_response_from(item: WorkspaceListItem) -> WorkspaceMembershipResponse {
    WorkspaceMembershipResponse {
        id: item.id,
        name: item.name,
        slug: item.slug,
        icon: item.icon,
        description: item.description,
        is_personal: item.is_personal,
        role_kind: item.role_kind,
        system_role: item.system_role,
        custom_role_id: item.custom_role_id,
        is_default: item.is_default,
    }
}

fn session_response_from(
    record: UserSessionRecord,
    current_session_id: Option<Uuid>,
) -> SessionResponse {
    SessionResponse {
        id: record.id,
        workspace_id: record.workspace_id,
        user_agent: record.user_agent,
        ip_address: record.ip_address,
        remember_me: record.remember_me,
        created_at: record.created_at,
        last_seen_at: record.last_seen_at,
        expires_at: record.expires_at,
        current: current_session_id.map_or(false, |id| id == record.id),
    }
}

async fn build_user_response(
    ctx: &AppContext,
    user: UserDto,
    preferred_workspace_id: Option<Uuid>,
) -> Result<UserResponse, StatusCode> {
    let workspaces = ctx
        .workspace_service()
        .list_for_user(user.id)
        .await
        .map_err(map_workspace_error)?
        .into_iter()
        .map(workspace_response_from)
        .collect::<Vec<_>>();
    let mut active_workspace_id =
        preferred_workspace_id.and_then(|id| workspaces.iter().find(|w| w.id == id).map(|w| w.id));
    if active_workspace_id.is_none() {
        active_workspace_id = workspaces.iter().find(|w| w.is_default).map(|w| w.id);
    }
    if active_workspace_id.is_none() {
        active_workspace_id = workspaces.first().map(|w| w.id);
    }
    let active_workspace =
        active_workspace_id.and_then(|id| workspaces.iter().find(|w| w.id == id).cloned());
    let mut active_workspace_permissions = Vec::new();
    if let Some(active_ws_id) = active_workspace_id {
        if let Some(set) = ctx
            .workspace_service()
            .resolve_permission_set(active_ws_id, user.id)
            .await
            .map_err(map_workspace_error)?
        {
            active_workspace_permissions = set.to_vec();
        }
    }
    Ok(UserResponse {
        id: user.id,
        email: user.email,
        name: user.name,
        workspaces,
        active_workspace_id,
        active_workspace,
        active_workspace_permissions,
    })
}

#[utoipa::path(post, path = "/api/auth/register", tag = "Auth", request_body = RegisterRequest, security(()), responses(
    (status = 200, body = UserResponse)
))]
pub async fn register(
    State(ctx): State<AppContext>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<UserResponse>, StatusCode> {
    let service = ctx.account_service();
    let user = service
        .register(&req.email, &req.name, &req.password)
        .await
        .map_err(map_account_error)?;
    let response = build_user_response(&ctx, user, None).await?;
    Ok(Json(response))
}

#[utoipa::path(post, path = "/api/auth/login", tag = "Auth", request_body = LoginRequest, security(()), responses(
    (status = 200, body = LoginResponse)
))]
pub async fn login(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<(HeaderMap, Json<LoginResponse>), StatusCode> {
    let service = ctx.account_service();
    let user = service
        .login(&req.email, &req.password)
        .await
        .map_err(map_account_error)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let user = build_user_response(&ctx, user, None).await?;
    let active_workspace_id = user
        .active_workspace_id
        .or_else(|| user.workspaces.iter().find(|w| w.is_default).map(|w| w.id))
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let client_ip = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);
    let issued = ctx
        .session_service()
        .issue_new_session(
            user.id,
            active_workspace_id,
            req.remember_me,
            SessionMetadata {
                user_agent,
                ip_address: client_ip.as_deref(),
            },
        )
        .await
        .map_err(map_auth_error)?;

    let mut response_headers = HeaderMap::new();
    apply_session_cookies(&ctx, &mut response_headers, &issued);

    Ok((
        response_headers,
        Json(LoginResponse {
            access_token: issued.access.token,
            user,
        }),
    ))
}

#[utoipa::path(post, path = "/api/auth/refresh", tag = "Auth", responses(
    (status = 200, body = RefreshResponse)
))]
pub async fn refresh_session(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<RefreshResponse>), StatusCode> {
    let refresh_token = extract_refresh_token(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let client_ip = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);
    let issued = ctx
        .session_service()
        .refresh_session(
            &refresh_token,
            None,
            SessionMetadata {
                user_agent,
                ip_address: client_ip.as_deref(),
            },
        )
        .await
        .map_err(map_auth_error)?;

    let mut response_headers = HeaderMap::new();
    apply_session_cookies(&ctx, &mut response_headers, &issued);
    Ok((
        response_headers,
        Json(RefreshResponse {
            access_token: issued.access.token,
        }),
    ))
}

#[utoipa::path(get, path = "/api/auth/me", tag = "Auth", responses((status = 200, body = UserResponse)))]
pub async fn me(
    State(ctx): State<AppContext>,
    bearer: Result<Bearer, StatusCode>,
    headers: HeaderMap,
) -> Result<Json<UserResponse>, StatusCode> {
    let bearer = bearer?;
    let bearer_token = bearer.0.clone();
    let sub = validate_bearer_str(&ctx, &bearer_token).await?;
    let id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let active_workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        id,
    )
    .await
    .map(Some)
    .or_else(|err| {
        if err == StatusCode::FORBIDDEN {
            Ok(None)
        } else {
            Err(err)
        }
    })?;

    let service = ctx.account_service();
    let row = service
        .get_me(id)
        .await
        .map_err(map_account_error)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let resp = build_user_response(&ctx, row, active_workspace_id).await?;
    Ok(Json(resp))
}

#[utoipa::path(delete, path = "/api/auth/me", tag = "Auth", responses((status = 204)))]
pub async fn delete_account(
    State(ctx): State<AppContext>,
    bearer: Bearer,
) -> Result<(HeaderMap, StatusCode), StatusCode> {
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let service = ctx.account_service();
    service
        .delete_account(user_id)
        .await
        .map_err(map_account_error)?;
    ctx.session_service()
        .revoke_all_for_user(user_id)
        .await
        .map_err(map_auth_error)?;

    let mut headers = HeaderMap::new();
    clear_auth_cookies(&mut headers, ctx.cfg.session_cookie_secure);

    Ok((headers, StatusCode::NO_CONTENT))
}

// --- Bearer extractor & JWT utils ---
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

#[derive(Debug, Clone)]
pub struct Bearer(pub String);

#[axum::async_trait]
impl<S> FromRequestParts<S> for Bearer
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // 1) Prefer Authorization header if present
        if let Some(auth) = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            if let Some(t) = auth.strip_prefix("Bearer ") {
                return Ok(Bearer(t.to_string()));
            }
        }

        // 2) Fallback to HttpOnly cookie `access_token`
        if let Some(cookie_hdr) = parts
            .headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
        {
            if let Some(token) = get_cookie(cookie_hdr, SESSION_COOKIE_NAME) {
                return Ok(Bearer(token));
            }
        }

        Err(StatusCode::UNAUTHORIZED)
    }
}

pub(crate) async fn validate_bearer(
    ctx: &AppContext,
    bearer: Bearer,
) -> Result<String, StatusCode> {
    validate_bearer_str(ctx, &bearer.0).await
}

pub async fn validate_bearer_public(
    ctx: &AppContext,
    bearer: Bearer,
) -> Result<String, StatusCode> {
    validate_bearer(ctx, bearer).await
}

pub async fn validate_bearer_str(ctx: &AppContext, token: &str) -> Result<String, StatusCode> {
    let service = ctx.auth_service();
    let session_service = ctx.session_service();
    let subject = service
        .subject_from_token(token)
        .await
        .map_err(map_auth_error)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
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
    if let Some(b) = bearer {
        match validate_bearer(ctx, b.clone()).await {
            Ok(sub) => {
                if let Ok(uid) = Uuid::parse_str(&sub) {
                    return Some(access::Actor::User(uid));
                }
            }
            Err(_) => {
                if let Some(actor) = resolve_actor_from_token_str(ctx, &b.0).await {
                    return Some(actor);
                }
            }
        }
    }
    if let Some(token) = share_token {
        return resolve_actor_from_token_str(ctx, token).await;
    }
    None
}

pub async fn resolve_actor_from_token_str(ctx: &AppContext, token: &str) -> Option<access::Actor> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return None;
    }
    let service = ctx.auth_service();
    if let Ok(Some(sub)) = service.subject_from_token(trimmed).await {
        if let Ok(uid) = Uuid::parse_str(&sub) {
            if let Some(session_id) = service.session_id_from_token_claim(trimmed) {
                if let Err(err) = ctx
                    .session_service()
                    .ensure_session_active(session_id)
                    .await
                {
                    if err.is_internal() {
                        error!(error = ?err, "session_validation_failed");
                    }
                    return None;
                }
            }
            return Some(access::Actor::User(uid));
        } else {
            return Some(access::Actor::Public);
        }
    }
    Some(access::Actor::ShareToken(trimmed.to_string()))
}

pub(crate) fn map_auth_error(err: ServiceError) -> StatusCode {
    if err.is_internal() {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::UNAUTHORIZED
    }
}

// --- Cookie helpers & logout ---

fn generate_oauth_state() -> String {
    OsRng
        .sample_iter(&Alphanumeric)
        .take(48)
        .map(char::from)
        .collect()
}

fn build_oauth_state_cookie(
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

fn clear_oauth_state_cookie(headers: &mut HeaderMap, secure: bool) {
    let secure_attr = if secure { "; Secure" } else { "" };
    append_cookie(
        headers,
        format!(
            "{}=; HttpOnly{}; Path=/; Max-Age=0; SameSite=Lax",
            OAUTH_STATE_COOKIE_NAME, secure_attr
        ),
    );
}

fn validate_oauth_state_cookie(
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, header};

    fn cookie_headers(
        provider: ExternalAuthProviderKind,
        state: &str,
        issued_at: i64,
    ) -> HeaderMap {
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
}

fn get_cookie(cookie_header: &str, name: &str) -> Option<String> {
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

fn append_cookie(headers: &mut HeaderMap, value: String) {
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

#[utoipa::path(post, path = "/api/auth/logout", tag = "Auth", responses((status = 204)))]
pub async fn logout(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
) -> Result<(HeaderMap, StatusCode), StatusCode> {
    if let Some(refresh_token) = extract_refresh_token(&headers) {
        if let Err(err) = ctx.session_service().revoke_by_token(&refresh_token).await {
            warn!(error = ?err, "logout_revoke_session_failed");
        }
    }
    let mut response_headers = HeaderMap::new();
    clear_auth_cookies(&mut response_headers, ctx.cfg.session_cookie_secure);
    clear_oauth_state_cookie(&mut response_headers, ctx.cfg.session_cookie_secure);
    Ok((response_headers, StatusCode::NO_CONTENT))
}

#[utoipa::path(get, path = "/api/auth/sessions", tag = "Auth", responses((status = 200, body = [SessionResponse])))]
pub async fn list_sessions(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionResponse>>, StatusCode> {
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let current_session_id = if let Some(refresh_token) = extract_refresh_token(&headers) {
        match ctx
            .session_service()
            .find_session_by_token(&refresh_token)
            .await
        {
            Ok(Some(session)) => Some(session.id),
            Ok(None) => None,
            Err(err) => {
                warn!(error = ?err, "resolve_current_session_failed");
                None
            }
        }
    } else {
        None
    };
    let sessions = ctx
        .session_service()
        .list_for_user(user_id)
        .await
        .map_err(map_auth_error)?;
    let now = Utc::now();
    let payload = sessions
        .into_iter()
        .filter(|session| session.revoked_at.is_none() && session.expires_at > now)
        .map(|session| session_response_from(session, current_session_id))
        .collect();
    Ok(Json(payload))
}

#[utoipa::path(delete, path = "/api/auth/sessions/{id}", tag = "Auth", params(("id" = Uuid, Path, description = "Session ID")), responses((status = 204)))]
pub async fn revoke_session(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Path(session_id): Path<Uuid>,
) -> Result<(HeaderMap, StatusCode), StatusCode> {
    let sub = validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let current_session_id = if let Some(refresh_token) = extract_refresh_token(&headers) {
        match ctx
            .session_service()
            .find_session_by_token(&refresh_token)
            .await
        {
            Ok(Some(session)) => Some(session.id),
            Ok(None) => None,
            Err(err) => {
                warn!(error = ?err, "resolve_current_session_failed");
                None
            }
        }
    } else {
        None
    };
    ctx.session_service()
        .revoke_session(user_id, session_id)
        .await
        .map_err(|err| match err {
            ServiceError::Forbidden => StatusCode::FORBIDDEN,
            ServiceError::NotFound => StatusCode::NOT_FOUND,
            other => map_auth_error(other),
        })?;
    let mut response_headers = HeaderMap::new();
    if current_session_id == Some(session_id) {
        clear_auth_cookies(&mut response_headers, ctx.cfg.session_cookie_secure);
    }
    Ok((response_headers, StatusCode::NO_CONTENT))
}
