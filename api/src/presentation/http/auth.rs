use crate::application::access;
use crate::application::services::errors::ServiceError;
use crate::presentation::context::AppContext;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tracing::error;
use utoipa::ToSchema;
use uuid::Uuid;

const SESSION_COOKIE_NAME: &str = "access_token";

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
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    pub access_token: String,
    pub user: UserResponse,
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/me", get(me).delete(delete_account))
        .with_state(ctx)
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
    Ok(Json(UserResponse {
        id: user.id,
        email: user.email,
        name: user.name,
    }))
}

#[utoipa::path(post, path = "/api/auth/login", tag = "Auth", request_body = LoginRequest, security(()), responses(
    (status = 200, body = LoginResponse)
))]
pub async fn login(
    State(ctx): State<AppContext>,
    Json(req): Json<LoginRequest>,
) -> Result<(HeaderMap, Json<LoginResponse>), StatusCode> {
    let service = ctx.account_service();
    let user = service
        .login(&req.email, &req.password)
        .await
        .map_err(map_account_error)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let user = UserResponse {
        id: user.id,
        email: user.email,
        name: user.name,
    };
    let session = ctx
        .auth_service()
        .issue_session(user.id)
        .map_err(map_auth_error)?;
    let cookie_value = build_session_cookie(
        &session.token,
        ctx.auth_service().session_ttl_secs(),
        ctx.cfg.session_cookie_secure,
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(&cookie_value)
            .unwrap_or(axum::http::HeaderValue::from_static("")),
    );

    Ok((
        headers,
        Json(LoginResponse {
            access_token: session.token,
            user,
        }),
    ))
}

#[utoipa::path(get, path = "/api/auth/me", tag = "Auth", responses((status = 200, body = UserResponse)))]
pub async fn me(
    State(ctx): State<AppContext>,
    bearer: Result<Bearer, StatusCode>,
) -> Result<Json<UserResponse>, StatusCode> {
    let sub = validate_bearer(&ctx, bearer?).await?;
    let id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let service = ctx.account_service();
    let row = service
        .get_me(id)
        .await
        .map_err(map_account_error)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    Ok(Json(UserResponse {
        id: row.id,
        email: row.email,
        name: row.name,
    }))
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

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(&clear_session_cookie(ctx.cfg.session_cookie_secure))
            .unwrap_or(axum::http::HeaderValue::from_static("")),
    );

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
    service
        .subject_from_token(token)
        .await
        .map_err(map_auth_error)?
        .ok_or(StatusCode::UNAUTHORIZED)
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
            return Some(access::Actor::User(uid));
        } else {
            return Some(access::Actor::Public);
        }
    }
    Some(access::Actor::ShareToken(trimmed.to_string()))
}

fn map_auth_error(err: ServiceError) -> StatusCode {
    if err.is_internal() {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::UNAUTHORIZED
    }
}

// --- Cookie helpers & logout ---

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

fn build_session_cookie(token: &str, max_age_secs: usize, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{}={}; HttpOnly{}; Path=/; Max-Age={}; SameSite=Lax",
        SESSION_COOKIE_NAME, token, secure_attr, max_age_secs
    )
}

fn clear_session_cookie(secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{}=; HttpOnly{}; Path=/; Max-Age=0; SameSite=Lax",
        SESSION_COOKIE_NAME, secure_attr
    )
}

#[utoipa::path(post, path = "/api/auth/logout", tag = "Auth", responses((status = 204)))]
pub async fn logout(State(ctx): State<AppContext>) -> Result<(HeaderMap, StatusCode), StatusCode> {
    // Clear cookie by setting it expired
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(&clear_session_cookie(ctx.cfg.session_cookie_secure))
            .unwrap_or(axum::http::HeaderValue::from_static("")),
    );
    Ok((headers, StatusCode::NO_CONTENT))
}
