use async_trait::async_trait;
use reqwest::Url;
use serde::Deserialize;
use tracing::warn;

use crate::application::services::auth::external::{
    ExternalAuthIdentity, ExternalAuthPayload, ExternalAuthProviderDescriptor,
    ExternalAuthProviderKind, ExternalAuthVerifier,
};
use crate::application::services::errors::ServiceError;
use crate::bootstrap::config::OidcOAuthConfig;

#[derive(Debug, Clone)]
pub struct OidcIdentityProvider {
    client: reqwest::Client,
    client_id: String,
    client_secret: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    default_redirect_uri: Option<String>,
    scopes: Vec<String>,
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OidcDiscoveryDocument {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OidcTokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OidcUserInfo {
    sub: String,
    email: Option<String>,
    #[serde(default, deserialize_with = "deserialize_opt_bool")]
    email_verified: Option<bool>,
    name: Option<String>,
    preferred_username: Option<String>,
    picture: Option<String>,
}

fn deserialize_opt_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    let Some(raw) = value else {
        return Ok(None);
    };
    match raw {
        serde_json::Value::Bool(flag) => Ok(Some(flag)),
        serde_json::Value::Number(num) => {
            if let Some(int) = num.as_i64() {
                Ok(Some(int != 0))
            } else if let Some(float) = num.as_f64() {
                Ok(Some(float != 0.0))
            } else {
                Ok(None)
            }
        }
        serde_json::Value::String(text) => {
            let normalized = text.trim().to_lowercase();
            if normalized.is_empty() {
                Ok(None)
            } else {
                Ok(Some(matches!(
                    normalized.as_str(),
                    "true" | "1" | "yes" | "y" | "t"
                )))
            }
        }
        _ => Ok(None),
    }
}

fn infer_display_name(issuer: &str) -> Option<String> {
    Url::parse(issuer)
        .ok()
        .and_then(|url| url.host_str().map(|host| host.to_string()))
}

impl OidcIdentityProvider {
    pub async fn discover(cfg: OidcOAuthConfig) -> anyhow::Result<Self> {
        let OidcOAuthConfig {
            issuer_url,
            discovery_url,
            client_id,
            client_secret,
            redirect_uri,
            mut scopes,
            display_name,
        } = cfg;

        let issuer = issuer_url.trim().to_string();
        if issuer.is_empty() {
            anyhow::bail!("oidc issuer url must not be empty");
        }
        let discovery_url = discovery_url
            .and_then(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
            .unwrap_or_else(|| {
                format!(
                    "{}/.well-known/openid-configuration",
                    issuer.trim_end_matches('/')
                )
            });
        let client = reqwest::Client::builder().build()?;
        let discovery: OidcDiscoveryDocument = client
            .get(&discovery_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let userinfo_endpoint = discovery
            .userinfo_endpoint
            .clone()
            .ok_or_else(|| anyhow::anyhow!("oidc discovery missing userinfo_endpoint"))?;
        if scopes.is_empty() {
            scopes = vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ]
        }
        Ok(Self {
            client,
            client_id,
            client_secret,
            authorization_endpoint: discovery.authorization_endpoint,
            token_endpoint: discovery.token_endpoint,
            userinfo_endpoint,
            default_redirect_uri: redirect_uri.and_then(|uri| {
                let trimmed = uri.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }),
            scopes,
            display_name: display_name.or_else(|| infer_display_name(&issuer)),
        })
    }

    fn resolve_redirect_uri(&self, provided: Option<String>) -> Option<String> {
        provided
            .and_then(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
            .or_else(|| self.default_redirect_uri.clone())
    }

    async fn fetch_userinfo(&self, access_token: &str) -> Result<OidcUserInfo, ServiceError> {
        self.client
            .get(&self.userinfo_endpoint)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|err| {
                warn!(error = ?err, "oidc_userinfo_request_failed");
                ServiceError::Unauthorized
            })?
            .json()
            .await
            .map_err(|err| {
                warn!(error = ?err, "oidc_userinfo_parse_failed");
                ServiceError::Unauthorized
            })
    }
}

#[async_trait]
impl ExternalAuthVerifier for OidcIdentityProvider {
    fn provider(&self) -> ExternalAuthProviderKind {
        ExternalAuthProviderKind::Oidc
    }

    fn descriptor(&self) -> ExternalAuthProviderDescriptor {
        let kind = self.provider();
        ExternalAuthProviderDescriptor {
            kind,
            requires_state: kind.requires_state(),
            client_ids: vec![self.client_id.clone()],
            redirect_uri: self.default_redirect_uri.clone(),
            display_name: self.display_name.clone(),
            authorization_url: Some(self.authorization_endpoint.clone()),
            scopes: self.scopes.clone(),
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
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];
        if let Some(uri) = redirect_uri {
            form.push(("redirect_uri".to_string(), uri));
        }
        let token_body: OidcTokenResponse = self
            .client
            .post(&self.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|err| {
                warn!(error = ?err, "oidc_token_request_failed");
                ServiceError::Unauthorized
            })?
            .json()
            .await
            .map_err(|err| {
                warn!(error = ?err, "oidc_token_response_parse_failed");
                ServiceError::Unauthorized
            })?;
        if let Some(error) = token_body.error {
            warn!(
                error = error.as_str(),
                description = token_body.error_description,
                "oidc_token_response_error"
            );
            return Err(ServiceError::Unauthorized);
        }
        let access_token = token_body.access_token.ok_or(ServiceError::Unauthorized)?;
        let user = self.fetch_userinfo(&access_token).await?;
        if user.sub.trim().is_empty() {
            return Err(ServiceError::Unauthorized);
        }
        let verified = user.email_verified.unwrap_or(false);
        let identity = ExternalAuthIdentity {
            provider: ExternalAuthProviderKind::Oidc,
            subject: user.sub,
            email: user.email.clone(),
            email_verified: verified,
            name: user
                .name
                .or(user.preferred_username)
                .or_else(|| user.email.clone()),
            avatar_url: user.picture,
        };
        Ok(identity)
    }
}
