use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;
use tracing::warn;

use crate::application::services::auth::external::{
    ExternalAuthIdentity, ExternalAuthPayload, ExternalAuthProviderKind, ExternalAuthVerifier,
};
use crate::application::services::errors::ServiceError;

const TOKENINFO_URL: &str = "https://oauth2.googleapis.com/tokeninfo";

#[derive(Debug, Clone)]
pub struct GoogleIdentityProvider {
    client: reqwest::Client,
    audiences: HashSet<String>,
}

impl GoogleIdentityProvider {
    pub fn new(client_ids: Vec<String>) -> anyhow::Result<Self> {
        let filtered: HashSet<String> = client_ids
            .into_iter()
            .map(|id| id.trim().to_string())
            .filter(|id| !id.is_empty())
            .collect();
        if filtered.is_empty() {
            anyhow::bail!("google client ids must not be empty");
        }
        Ok(Self {
            client: reqwest::Client::new(),
            audiences: filtered,
        })
    }
}

#[derive(Debug, Deserialize)]
struct GoogleTokenInfo {
    aud: String,
    sub: String,
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<String>,
    name: Option<String>,
    picture: Option<String>,
}

fn parse_email_verified(value: Option<String>) -> bool {
    match value.unwrap_or_default().to_lowercase().as_str() {
        "true" | "1" | "yes" => true,
        _ => false,
    }
}

#[async_trait]
impl ExternalAuthVerifier for GoogleIdentityProvider {
    fn provider(&self) -> ExternalAuthProviderKind {
        ExternalAuthProviderKind::Google
    }

    async fn verify(
        &self,
        payload: &ExternalAuthPayload,
    ) -> Result<ExternalAuthIdentity, ServiceError> {
        let credential = payload
            .credential
            .as_deref()
            .ok_or(ServiceError::BadRequest("missing_credential"))?;
        let res = self
            .client
            .get(TOKENINFO_URL)
            .query(&[("id_token", credential)])
            .send()
            .await
            .map_err(|err| {
                warn!(error = ?err, "google_tokeninfo_request_failed");
                ServiceError::Unauthorized
            })?;
        if !res.status().is_success() {
            warn!(
                status = %res.status(),
                "google_tokeninfo_request_rejected"
            );
            return Err(ServiceError::Unauthorized);
        }
        let token: GoogleTokenInfo = res.json().await.map_err(|err| {
            warn!(error = ?err, "google_tokeninfo_parse_failed");
            ServiceError::Unauthorized
        })?;
        if !self.audiences.contains(token.aud.trim()) {
            warn!(aud = token.aud, "google_tokeninfo_invalid_audience");
            return Err(ServiceError::Unauthorized);
        }
        let email_verified = parse_email_verified(token.email_verified);
        let identity = ExternalAuthIdentity {
            provider: ExternalAuthProviderKind::Google,
            subject: token.sub,
            email: token.email,
            email_verified,
            name: token.name,
            avatar_url: token.picture,
        };
        Ok(identity)
    }
}
