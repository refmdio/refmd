use std::sync::Arc;

use tracing::{info, warn};

use crate as api;

use api::application::services::auth::external::{ExternalAuthRegistry, ExternalAuthVerifier};
use api::application::services::auth::service::AuthService;
use api::application::services::auth::token_validation::TokenValidationService;
use api::application::services::auth::user_sessions::UserSessionService;
use api::bootstrap::config::Config;
use api::infrastructure::auth::github::GithubOAuthProvider;
use api::infrastructure::auth::google::GoogleIdentityProvider;
use api::infrastructure::auth::oidc::OidcIdentityProvider;

pub struct AuthStack {
    pub auth_service: Arc<AuthService>,
    pub session_service: Arc<UserSessionService>,
    pub external_auth: Arc<ExternalAuthRegistry>,
    pub cookie_secure: bool,
}

pub async fn build_auth_stack(
    cfg: &Config,
    token_validation_service: Arc<TokenValidationService>,
    user_session_repo: Arc<dyn api::application::ports::user_session_repository::UserSessionRepository>,
) -> anyhow::Result<AuthStack> {
    let external_auth = build_external_auth_registry(cfg).await?;

    let cookie_secure = cfg
        .frontend_url
        .as_deref()
        .map(|u| u.starts_with("https://"))
        .unwrap_or(false);

    let auth_service = Arc::new(AuthService::new(
        cfg.jwt_secret_pem.clone(),
        token_validation_service,
        cfg.jwt_expires_secs as usize,
    ));
    let session_service = Arc::new(UserSessionService::new(
        user_session_repo,
        auth_service.clone(),
        cfg.session_refresh_ttl_secs,
        cfg.session_refresh_remember_ttl_secs,
    ));

    Ok(AuthStack {
        auth_service,
        session_service,
        external_auth,
        cookie_secure,
    })
}

async fn build_external_auth_registry(cfg: &Config) -> anyhow::Result<Arc<ExternalAuthRegistry>> {
    let mut external_auth_providers: Vec<Arc<dyn ExternalAuthVerifier>> = Vec::new();

    if let Some(google_cfg) = cfg.google_oauth.clone() {
        match GoogleIdentityProvider::new(google_cfg.client_ids.clone()) {
            Ok(provider) => {
                info!("google_oauth_provider_enabled");
                external_auth_providers.push(Arc::new(provider));
            }
            Err(err) => {
                warn!(error = ?err, "google_oauth_provider_init_failed");
            }
        }
    }

    if let Some(github_cfg) = cfg.github_oauth.clone() {
        match GithubOAuthProvider::new(
            github_cfg.client_id.clone(),
            github_cfg.client_secret.clone(),
            github_cfg.redirect_uri.clone(),
        ) {
            Ok(provider) => {
                info!("github_oauth_provider_enabled");
                external_auth_providers.push(Arc::new(provider));
            }
            Err(err) => {
                warn!(error = ?err, "github_oauth_provider_init_failed");
            }
        }
    }

    if let Some(oidc_cfg) = cfg.oidc_oauth.clone() {
        match OidcIdentityProvider::discover(oidc_cfg).await {
            Ok(provider) => {
                info!("oidc_oauth_provider_enabled");
                external_auth_providers.push(Arc::new(provider));
            }
            Err(err) => {
                warn!(error = ?err, "oidc_oauth_provider_init_failed");
            }
        }
    }

    Ok(Arc::new(ExternalAuthRegistry::new(external_auth_providers)))
}
