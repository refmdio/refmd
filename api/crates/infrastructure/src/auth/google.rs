use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;
use tracing::warn;

use application::services::auth::external::{
    ExternalAuthIdentity, ExternalAuthPayload, ExternalAuthProviderDescriptor,
    ExternalAuthProviderKind, ExternalAuthVerifier,
};
use application::services::errors::ServiceError;

const TOKENINFO_URL: &str = "https://oauth2.googleapis.com/tokeninfo";

#[derive(Debug, Clone)]
pub struct GoogleIdentityProvider {
    client: reqwest::Client,
    audiences: HashSet<String>,
    audience_list: Vec<String>,
}

impl GoogleIdentityProvider {
    pub fn new(client_ids: Vec<String>) -> anyhow::Result<Self> {
        let mut audiences = HashSet::new();
        let mut ordered: Vec<String> = Vec::new();
        for id in client_ids {
            let trimmed = id.trim();
            if trimmed.is_empty() {
                continue;
            }
            let value = trimmed.to_string();
            if audiences.insert(value.clone()) {
                ordered.push(value);
            }
        }
        if audiences.is_empty() {
            anyhow::bail!("google client ids must not be empty");
        }
        Ok(Self {
            client: reqwest::Client::new(),
            audiences,
            audience_list: ordered,
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

    fn descriptor(&self) -> ExternalAuthProviderDescriptor {
        let kind = self.provider();
        ExternalAuthProviderDescriptor {
            kind,
            requires_state: kind.requires_state(),
            client_ids: self.audience_list.clone(),
            redirect_uri: None,
            display_name: Some("Google".to_string()),
            authorization_url: None,
            scopes: Vec::new(),
        }
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
