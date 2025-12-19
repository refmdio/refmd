use std::sync::Arc;

use tracing::{info, warn};

use crate::config::Config;
use application::identity::ports::jwt_codec::JwtCodec;
use application::identity::ports::secret_hasher::SecretHasher;
use application::identity::services::auth::auth_service::AuthService;
use application::identity::services::auth::external::{ExternalAuthRegistry, ExternalAuthVerifier};
use application::identity::services::auth::token_validation::TokenValidationService;
use application::identity::services::auth::user_sessions::UserSessionService;
use infrastructure::identity::auth::github::GithubOAuthProvider;
use infrastructure::identity::auth::google::GoogleIdentityProvider;
use infrastructure::identity::auth::oidc::{OidcIdentityProvider, OidcOAuthProviderConfig};
use infrastructure::identity::jwt::Hs256JwtCodec;

pub struct AuthStack {
    pub auth_service: Arc<AuthService>,
    pub session_service: Arc<UserSessionService>,
    pub external_auth: Arc<ExternalAuthRegistry>,
    pub cookie_secure: bool,
}

pub async fn build_auth_stack(
    cfg: &Config,
    token_validation_service: Arc<TokenValidationService>,
    secret_hasher: Arc<dyn SecretHasher>,
    user_session_repo: Arc<
        dyn application::identity::ports::user_session_repository::UserSessionRepository,
    >,
) -> anyhow::Result<AuthStack> {
    let external_auth = build_external_auth_registry(cfg).await?;

    let cookie_secure = cfg
        .frontend_url
        .as_deref()
        .map(|u| u.starts_with("https://"))
        .unwrap_or(false);

    let jwt: Arc<dyn JwtCodec> = Arc::new(Hs256JwtCodec::new(cfg.jwt_secret_pem.clone()));
    let auth_service = Arc::new(AuthService::new(
        jwt,
        token_validation_service,
        cfg.jwt_expires_secs as usize,
    ));
    let session_service = Arc::new(UserSessionService::new(
        user_session_repo,
        secret_hasher,
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
        let cfg = OidcOAuthProviderConfig {
            issuer_url: oidc_cfg.issuer_url,
            discovery_url: oidc_cfg.discovery_url,
            client_id: oidc_cfg.client_id,
            client_secret: oidc_cfg.client_secret,
            redirect_uri: oidc_cfg.redirect_uri,
            scopes: oidc_cfg.scopes,
            display_name: oidc_cfg.display_name,
        };
        match OidcIdentityProvider::discover(cfg).await {
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
