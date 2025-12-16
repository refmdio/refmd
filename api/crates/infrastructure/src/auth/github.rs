use async_trait::async_trait;
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue, USER_AGENT};
use serde::Deserialize;
use tracing::warn;

use application::services::auth::external::{
    ExternalAuthIdentity, ExternalAuthPayload, ExternalAuthProviderDescriptor,
    ExternalAuthProviderKind, ExternalAuthVerifier,
};
use application::services::errors::ServiceError;

const AUTH_URL: &str = "https://github.com/login/oauth/authorize";
const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const USER_URL: &str = "https://api.github.com/user";
const USER_EMAILS_URL: &str = "https://api.github.com/user/emails";

#[derive(Debug, Clone)]
pub struct GithubOAuthProvider {
    client: reqwest::Client,
    client_id: String,
    client_secret: String,
    default_redirect_uri: Option<String>,
}

impl GithubOAuthProvider {
    pub fn new(
        client_id: String,
        client_secret: String,
        default_redirect_uri: Option<String>,
    ) -> anyhow::Result<Self> {
        if client_id.trim().is_empty() || client_secret.trim().is_empty() {
            anyhow::bail!("github oauth client id/secret must be provided");
        }
        let client = reqwest::Client::builder().build()?;
        Ok(Self {
            client,
            client_id,
            client_secret,
            default_redirect_uri: default_redirect_uri.and_then(|uri| {
                if uri.trim().is_empty() {
                    None
                } else {
                    Some(uri)
                }
            }),
        })
    }

    fn resolve_redirect_uri(&self, provided: Option<String>) -> Option<String> {
        provided
            .and_then(|v| {
                let trimmed = v.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
            .or_else(|| self.default_redirect_uri.clone())
    }

    async fn resolve_verified_email(
        &self,
        headers: HeaderMap,
        access_token: &str,
        profile_email: Option<&str>,
    ) -> Result<String, ServiceError> {
        let emails: Vec<GithubEmail> = self
            .client
            .get(USER_EMAILS_URL)
            .headers(headers)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|err| {
                warn!(error = ?err, "github_emails_request_failed");
                ServiceError::Unauthorized
            })?
            .json()
            .await
            .map_err(|err| {
                warn!(error = ?err, "github_emails_parse_failed");
                ServiceError::Unauthorized
            })?;

        let mut preferred: Option<String> = None;
        let mut fallback: Option<String> = None;

        for entry in emails {
            if !entry.verified {
                continue;
            }
            if let Some(profile) = profile_email {
                if profile.eq_ignore_ascii_case(&entry.email) {
                    return Ok(entry.email);
                }
            }
            if entry.primary && preferred.is_none() {
                preferred = Some(entry.email.clone());
            }
            if fallback.is_none() {
                fallback = Some(entry.email);
            }
        }

        preferred
            .or(fallback)
            .ok_or(ServiceError::BadRequest("email_required"))
    }
}

#[derive(Debug, Deserialize)]
struct GithubTokenResponse {
    access_token: Option<String>,
    #[serde(rename = "scope")]
    _scope: Option<String>,
    #[serde(rename = "token_type")]
    _token_type: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GithubUser {
    id: u64,
    login: String,
    name: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GithubEmail {
    email: String,
    verified: bool,
    primary: bool,
}

fn build_default_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github+json"),
    );
    headers.insert(USER_AGENT, HeaderValue::from_static("refmd-auth-client"));
    headers
}

#[async_trait]
impl ExternalAuthVerifier for GithubOAuthProvider {
    fn provider(&self) -> ExternalAuthProviderKind {
        ExternalAuthProviderKind::Github
    }

    fn descriptor(&self) -> ExternalAuthProviderDescriptor {
        let kind = self.provider();
        ExternalAuthProviderDescriptor {
            kind,
            requires_state: kind.requires_state(),
            client_ids: vec![self.client_id.clone()],
            redirect_uri: self.default_redirect_uri.clone(),
            display_name: Some("GitHub".to_string()),
            authorization_url: Some(AUTH_URL.to_string()),
            scopes: vec!["read:user".to_string(), "user:email".to_string()],
        }
    }

    async fn verify(
        &self,
        payload: &ExternalAuthPayload,
    ) -> Result<ExternalAuthIdentity, ServiceError> {
        let code = payload
            .code
            .as_deref()
            .ok_or(ServiceError::BadRequest("missing_code"))?;
        let redirect_uri = self.resolve_redirect_uri(payload.redirect_uri.clone());
        let mut form = vec![
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("code", code),
        ];
        if let Some(uri) = redirect_uri.as_deref() {
            form.push(("redirect_uri", uri));
        }

        let token_resp = self
            .client
            .post(TOKEN_URL)
            .header(ACCEPT, "application/json")
            .form(&form)
            .send()
            .await
            .map_err(|err| {
                warn!(error = ?err, "github_token_request_failed");
                ServiceError::Unauthorized
            })?;
        let token_body: GithubTokenResponse = token_resp.json().await.map_err(|err| {
            warn!(error = ?err, "github_token_response_parse_failed");
            ServiceError::Unauthorized
        })?;
        if let Some(error) = token_body.error {
            warn!(
                error = error.as_str(),
                description = token_body.error_description,
                "github_token_response_error"
            );
            return Err(ServiceError::Unauthorized);
        }
        let access_token = token_body
            .access_token
            .ok_or_else(|| ServiceError::Unauthorized)?;

        let headers = build_default_headers();
        let user: GithubUser = self
            .client
            .get(USER_URL)
            .headers(headers.clone())
            .bearer_auth(&access_token)
            .send()
            .await
            .map_err(|err| {
                warn!(error = ?err, "github_user_request_failed");
                ServiceError::Unauthorized
            })?
            .json()
            .await
            .map_err(|err| {
                warn!(error = ?err, "github_user_parse_failed");
                ServiceError::Unauthorized
            })?;

        let email = self
            .resolve_verified_email(headers, &access_token, user.email.as_deref())
            .await?;

        Ok(ExternalAuthIdentity {
            provider: ExternalAuthProviderKind::Github,
            subject: user.id.to_string(),
            email: Some(email),
            email_verified: true,
            name: user.name.or_else(|| Some(user.login)),
            avatar_url: user.avatar_url,
        })
    }
}
