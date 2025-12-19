use application::core::services::errors::ServiceError;
use application::identity::dtos::UserDto;
use application::identity::ports::user_session_repository::UserSessionRecord;
use application::identity::services::auth::external::{
    ExternalAuthPayload, ExternalAuthProviderKind,
};
use application::identity::services::auth::user_sessions::SessionMetadata;
use application::workspaces::ports::workspace_repository::WorkspaceListItem;
use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::Utc;
use tracing::warn;
use uuid::Uuid;

use crate::context::AppContext;
use crate::http::workspaces::scope as workspace_scope;

use super::cookies::{
    append_cookie, build_oauth_state_cookie, clear_oauth_state_cookie, extract_client_ip,
    extract_refresh_token, extract_user_agent, generate_oauth_state, validate_oauth_state_cookie,
};
use super::security::{RefreshedSession, map_auth_error, validate_bearer, validate_bearer_str};
use super::{
    AuthProviderInfoResponse, AuthProvidersResponse, LoginRequest, LoginResponse,
    OAuthLoginRequest, OAuthStateResponse, RefreshResponse, RegisterRequest, SessionResponse,
    UserResponse, apply_session_cookies, clear_auth_cookies,
};

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
    params(("provider" = String, Path, description = "OAuth provider identifier (e.g., google)")),
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

#[utoipa::path(
    get,
    path = "/api/auth/providers",
    tag = "Auth",
    security(()),
    responses((status = 200, body = AuthProvidersResponse))
)]
pub async fn list_oauth_providers(
    State(ctx): State<AppContext>,
) -> Result<Json<AuthProvidersResponse>, StatusCode> {
    let providers = ctx
        .external_auth()
        .list_descriptors()
        .into_iter()
        .map(|descriptor| AuthProviderInfoResponse {
            id: descriptor.kind.as_str().to_string(),
            requires_state: descriptor.requires_state,
            client_ids: descriptor.client_ids,
            redirect_uri: descriptor.redirect_uri,
            name: descriptor.display_name,
            authorization_url: descriptor.authorization_url,
            scopes: descriptor.scopes,
        })
        .collect();
    Ok(Json(AuthProvidersResponse { providers }))
}

fn map_account_error(err: ServiceError) -> StatusCode {
    crate::http::error::map_service_error(err, "account_service_error")
}

fn map_workspace_error(err: ServiceError) -> StatusCode {
    crate::http::error::map_service_error(err, "workspace_service_error")
}

fn workspace_response_from(item: WorkspaceListItem) -> super::WorkspaceMembershipResponse {
    super::WorkspaceMembershipResponse {
        id: item.id,
        name: item.name,
        slug: item.slug,
        icon: item.icon,
        description: item.description,
        is_personal: item.is_personal,
        role_kind: item.role_kind.as_str().to_string(),
        system_role: item.system_role.map(|role| role.as_str().to_string()),
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

#[utoipa::path(
    post,
    path = "/api/auth/register",
    tag = "Auth",
    request_body = RegisterRequest,
    security(()),
    responses((status = 200, body = UserResponse))
)]
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

#[utoipa::path(
    post,
    path = "/api/auth/login",
    tag = "Auth",
    request_body = LoginRequest,
    security(()),
    responses((status = 200, body = LoginResponse))
)]
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

#[utoipa::path(
    post,
    path = "/api/auth/refresh",
    tag = "Auth",
    responses((status = 200, body = RefreshResponse))
)]
pub async fn refresh_session(
    State(ctx): State<AppContext>,
    refreshed: Option<Extension<RefreshedSession>>,
) -> Result<axum::response::Response, StatusCode> {
    if let Some(Extension(bundle)) = refreshed {
        return Ok(Json(RefreshResponse {
            access_token: bundle.0.access.token.clone(),
        })
        .into_response());
    }

    let mut response_headers = HeaderMap::new();
    clear_auth_cookies(&mut response_headers, ctx.cfg.session_cookie_secure);
    Ok((response_headers, StatusCode::UNAUTHORIZED).into_response())
}

#[utoipa::path(get, path = "/api/auth/me", tag = "Auth", responses((status = 200, body = UserResponse)))]
pub async fn me(
    State(ctx): State<AppContext>,
    bearer: Result<super::Bearer, StatusCode>,
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
    bearer: super::Bearer,
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
    bearer: super::Bearer,
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

#[utoipa::path(
    delete,
    path = "/api/auth/sessions/{id}",
    tag = "Auth",
    params(("id" = Uuid, Path, description = "Session ID")),
    responses((status = 204))
)]
pub async fn revoke_session(
    State(ctx): State<AppContext>,
    bearer: super::Bearer,
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
