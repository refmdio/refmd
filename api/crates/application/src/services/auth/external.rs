use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::services::errors::ServiceError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalAuthProviderKind {
    Google,
    Github,
    Oidc,
}

impl ExternalAuthProviderKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExternalAuthProviderKind::Google => "google",
            ExternalAuthProviderKind::Github => "github",
            ExternalAuthProviderKind::Oidc => "oidc",
        }
    }

    pub fn requires_state(&self) -> bool {
        matches!(
            self,
            ExternalAuthProviderKind::Github | ExternalAuthProviderKind::Oidc
        )
    }
}

impl TryFrom<&str> for ExternalAuthProviderKind {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "google" => Ok(ExternalAuthProviderKind::Google),
            "github" => Ok(ExternalAuthProviderKind::Github),
            "oidc" => Ok(ExternalAuthProviderKind::Oidc),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExternalAuthProviderDescriptor {
    pub kind: ExternalAuthProviderKind,
    pub requires_state: bool,
    pub client_ids: Vec<String>,
    pub redirect_uri: Option<String>,
    pub display_name: Option<String>,
    pub authorization_url: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ExternalAuthPayload {
    pub credential: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
}

impl ExternalAuthPayload {
    pub fn empty() -> Self {
        Self {
            credential: None,
            code: None,
            redirect_uri: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExternalAuthIdentity {
    pub provider: ExternalAuthProviderKind,
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

#[async_trait]
pub trait ExternalAuthVerifier: Send + Sync {
    fn provider(&self) -> ExternalAuthProviderKind;
    fn descriptor(&self) -> ExternalAuthProviderDescriptor;
    async fn verify(
        &self,
        payload: &ExternalAuthPayload,
    ) -> Result<ExternalAuthIdentity, ServiceError>;
}

#[derive(Clone, Default)]
pub struct ExternalAuthRegistry {
    providers: HashMap<ExternalAuthProviderKind, Arc<dyn ExternalAuthVerifier>>,
}

impl ExternalAuthRegistry {
    pub fn new(providers: Vec<Arc<dyn ExternalAuthVerifier>>) -> Self {
        let mut map = HashMap::new();
        for provider in providers {
            map.insert(provider.provider(), provider);
        }
        Self { providers: map }
    }

    pub fn get(&self, provider: ExternalAuthProviderKind) -> Option<Arc<dyn ExternalAuthVerifier>> {
        self.providers.get(&provider).cloned()
    }

    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    pub fn list_descriptors(&self) -> Vec<ExternalAuthProviderDescriptor> {
        self.providers
            .values()
            .map(|provider| provider.descriptor())
            .collect()
    }
}
