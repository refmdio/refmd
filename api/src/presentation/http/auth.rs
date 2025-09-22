use crate::application::access;
use crate::application::use_cases::auth::login::{Login as LoginUc, LoginRequest as LoginDto};
use crate::application::use_cases::auth::me::GetMe;
use crate::application::use_cases::auth::register::{
    Register as RegisterUc, RegisterRequest as RegisterDto,
};
use crate::bootstrap::app_context::AppContext;
use crate::bootstrap::config::Config;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

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

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/me", get(me))
        .with_state(ctx)
}

#[utoipa::path(post, path = "/api/auth/register", tag = "Auth", request_body = RegisterRequest, security(()), responses(
    (status = 200, body = UserResponse)
))]
pub async fn register(
    State(ctx): State<AppContext>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<UserResponse>, StatusCode> {
    let repo = ctx.user_repo();
    let uc = RegisterUc {
        repo: repo.as_ref(),
    };
    let dto = RegisterDto {
        email: req.email.clone(),
        name: req.name.clone(),
        password: req.password.clone(),
    };
    let user = uc.execute(&dto).await.map_err(|_| StatusCode::CONFLICT)?;
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
    let repo = ctx.user_repo();
    let uc = LoginUc {
        repo: repo.as_ref(),
    };
    let dto = LoginDto {
        email: req.email.clone(),
        password: req.password.clone(),
    };
    let user = uc
        .execute(&dto)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let user = UserResponse {
        id: user.id,
        email: user.email,
        name: user.name,
    };
    let now = chrono::Utc::now().timestamp() as usize;
    let claims = Claims {
        sub: user.id.to_string(),
        exp: now + (ctx.cfg.jwt_expires_secs as usize),
    };
    let token = jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(ctx.cfg.jwt_secret_pem.as_bytes()),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Set HttpOnly cookie with the access token
    let mut headers = HeaderMap::new();
    let secure = ctx
        .cfg
        .frontend_url
        .as_deref()
        .map(|u| u.starts_with("https://"))
        .unwrap_or(false);
    let cookie = build_access_cookie(&token, ctx.cfg.jwt_expires_secs, secure);
    headers.insert(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(&cookie)
            .unwrap_or(axum::http::HeaderValue::from_static("")),
    );

    Ok((
        headers,
        Json(LoginResponse {
            access_token: token,
            user,
        }),
    ))
}

#[utoipa::path(get, path = "/api/auth/me", tag = "Auth", responses((status = 200, body = UserResponse)))]
pub async fn me(
    State(ctx): State<AppContext>,
    bearer: Result<Bearer, StatusCode>,
) -> Result<Json<UserResponse>, StatusCode> {
    let sub = validate_bearer(&ctx.cfg, bearer?)?;
    let id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let repo = ctx.user_repo();
    let uc = GetMe {
        repo: repo.as_ref(),
    };
    let row = uc
        .execute(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    Ok(Json(UserResponse {
        id: row.id,
        email: row.email,
        name: row.name,
    }))
}

// --- Bearer extractor & JWT utils ---
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

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
            if let Some(token) = get_cookie(cookie_hdr, "access_token") {
                return Ok(Bearer(token));
            }
        }

        Err(StatusCode::UNAUTHORIZED)
    }
}

pub(crate) fn validate_bearer(cfg: &Config, bearer: Bearer) -> Result<String, StatusCode> {
    let token = bearer.0;
    let data = jsonwebtoken::decode::<Claims>(
        &token,
        &DecodingKey::from_secret(cfg.jwt_secret_pem.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(data.claims.sub)
}

pub fn validate_bearer_public(cfg: &Config, bearer: Bearer) -> Result<String, StatusCode> {
    validate_bearer(cfg, bearer)
}

pub fn validate_bearer_str(cfg: &Config, token: &str) -> Result<String, StatusCode> {
    let data = jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(cfg.jwt_secret_pem.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(data.claims.sub)
}

pub fn resolve_actor_from_parts(
    cfg: &Config,
    bearer: Option<Bearer>,
    share_token: Option<&str>,
) -> Option<access::Actor> {
    if let Some(b) = bearer {
        if let Ok(sub) = validate_bearer(cfg, b) {
            if let Ok(uid) = Uuid::parse_str(&sub) {
                return Some(access::Actor::User(uid));
            }
        }
    }
    share_token.and_then(|t| resolve_actor_from_token_str(cfg, t))
}

pub fn resolve_actor_from_token_str(cfg: &Config, token: &str) -> Option<access::Actor> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(sub) = validate_bearer_str(cfg, trimmed) {
        if let Ok(uid) = Uuid::parse_str(&sub) {
            return Some(access::Actor::User(uid));
        } else {
            return Some(access::Actor::Public);
        }
    }
    Some(access::Actor::ShareToken(trimmed.to_string()))
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

fn build_access_cookie(token: &str, max_age_secs: i64, secure: bool) -> String {
    // Note: SameSite=Lax for typical same-site SPA/API setups.
    // In cross-site deployments, consider SameSite=None; Secure and CSRF protection.
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "access_token={}; HttpOnly{}; Path=/; Max-Age={}; SameSite=Lax",
        token,
        secure_attr,
        max_age_secs.max(0)
    )
}

#[utoipa::path(post, path = "/api/auth/logout", tag = "Auth", responses((status = 204)))]
pub async fn logout(State(ctx): State<AppContext>) -> Result<(HeaderMap, StatusCode), StatusCode> {
    // Clear cookie by setting it expired
    let mut headers = HeaderMap::new();
    let secure = ctx
        .cfg
        .frontend_url
        .as_deref()
        .map(|u| u.starts_with("https://"))
        .unwrap_or(false);
    let cookie = if secure {
        "access_token=; HttpOnly; Secure; Path=/; Max-Age=0; SameSite=Lax"
    } else {
        "access_token=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax"
    };
    headers.insert(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(cookie)
            .unwrap_or(axum::http::HeaderValue::from_static("")),
    );
    Ok((headers, StatusCode::NO_CONTENT))
}
