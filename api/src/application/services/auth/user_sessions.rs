use std::sync::Arc;

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use chrono::{DateTime, Duration, Utc};
use rand::{Rng, distributions::Alphanumeric, rngs::OsRng};
use uuid::Uuid;

use crate::application::ports::user_session_repository::{
    UserSessionRecord, UserSessionRepository,
};
use crate::application::services::api_tokens::{compute_digest, verify_token};
use crate::application::services::auth::service::{AuthService, IssuedSession};
use crate::application::services::errors::ServiceError;

pub struct SessionMetadata<'a> {
    pub user_agent: Option<&'a str>,
    pub ip_address: Option<&'a str>,
}

pub struct IssuedSessionBundle {
    pub access: IssuedSession,
    pub refresh_token: String,
    pub refresh_expires_at: DateTime<Utc>,
    pub session: UserSessionRecord,
}

pub struct UserSessionService {
    repo: Arc<dyn UserSessionRepository>,
    auth: Arc<AuthService>,
    refresh_ttl_secs: i64,
    refresh_ttl_long_secs: i64,
}

impl UserSessionService {
    pub fn new(
        repo: Arc<dyn UserSessionRepository>,
        auth: Arc<AuthService>,
        refresh_ttl_secs: i64,
        refresh_ttl_long_secs: i64,
    ) -> Self {
        Self {
            repo,
            auth,
            refresh_ttl_secs,
            refresh_ttl_long_secs,
        }
    }

    fn ttl_for(&self, remember_me: bool) -> Duration {
        let secs = if remember_me {
            self.refresh_ttl_long_secs.max(self.refresh_ttl_secs)
        } else {
            self.refresh_ttl_secs
        };
        Duration::seconds(secs.max(60))
    }

    fn sanitize_metadata<'a>(value: Option<&'a str>) -> Option<&'a str> {
        value.and_then(|raw| {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
    }

    fn clamp_string(value: Option<&str>, max_len: usize) -> Option<String> {
        Self::sanitize_metadata(value).map(|s| {
            let mut owned = s.to_string();
            if owned.len() > max_len {
                owned.truncate(max_len);
            }
            owned
        })
    }

    fn generate_refresh_token() -> anyhow::Result<(String, String, String)> {
        let random: String = OsRng
            .sample_iter(&Alphanumeric)
            .take(48)
            .map(char::from)
            .collect();
        let plaintext = format!("rmds_{random}");
        let salt = SaltString::generate(&mut OsRng);
        let argon = Argon2::default();
        let hash = argon
            .hash_password(plaintext.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?
            .to_string();
        let digest = compute_digest(&plaintext);
        Ok((plaintext, hash, digest))
    }

    fn metadata<'a>(&self, meta: &'a SessionMetadata<'a>) -> (Option<String>, Option<String>) {
        (
            Self::clamp_string(meta.user_agent, 500),
            Self::clamp_string(meta.ip_address, 100),
        )
    }

    pub async fn issue_new_session(
        &self,
        user_id: Uuid,
        workspace_id: Uuid,
        remember_me: bool,
        meta: SessionMetadata<'_>,
    ) -> Result<IssuedSessionBundle, ServiceError> {
        let ttl = self.ttl_for(remember_me);
        let expires_at = Utc::now() + ttl;
        let (refresh_token, token_hash, token_digest) =
            Self::generate_refresh_token().map_err(ServiceError::Unexpected)?;
        let (user_agent, ip_address) = self.metadata(&meta);
        let record = self
            .repo
            .create(
                user_id,
                workspace_id,
                &token_hash,
                &token_digest,
                expires_at,
                remember_me,
                user_agent.as_deref(),
                ip_address.as_deref(),
            )
            .await
            .map_err(ServiceError::from)?;
        let access = self
            .auth
            .issue_session(user_id, workspace_id, Some(record.id))
            .map_err(ServiceError::from)?;
        Ok(IssuedSessionBundle {
            access,
            refresh_token,
            refresh_expires_at: expires_at,
            session: record,
        })
    }

    pub async fn refresh_session(
        &self,
        token: &str,
        workspace_override: Option<Uuid>,
        meta: SessionMetadata<'_>,
    ) -> Result<IssuedSessionBundle, ServiceError> {
        let digest = compute_digest(token);
        let secret = self
            .repo
            .find_by_digest(&digest)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::Unauthorized)?;
        if secret.session.revoked_at.is_some() {
            return Err(ServiceError::Unauthorized);
        }
        let now = Utc::now();
        if secret.session.expires_at <= now {
            let _ = self.repo.revoke(secret.session.id).await;
            return Err(ServiceError::Unauthorized);
        }
        if !verify_token(token, &secret.token_hash).map_err(ServiceError::from)? {
            let _ = self.repo.revoke(secret.session.id).await;
            return Err(ServiceError::Unauthorized);
        }

        let remember_me = secret.session.remember_me;
        let ttl = self.ttl_for(remember_me);
        let expires_at = now + ttl;
        let (refresh_token, token_hash, token_digest) =
            Self::generate_refresh_token().map_err(ServiceError::Unexpected)?;
        let (user_agent, ip_address) = self.metadata(&meta);

        let mut session = secret.session;
        if let Some(workspace_id) = workspace_override {
            session.workspace_id = workspace_id;
            let updated = self
                .repo
                .update_workspace(session.id, workspace_id)
                .await
                .map_err(ServiceError::from)?;
            if !updated {
                return Err(ServiceError::Unauthorized);
            }
        }

        session.expires_at = expires_at;
        session.last_seen_at = now;
        session.user_agent = user_agent.clone();
        session.ip_address = ip_address.clone();

        let updated = self
            .repo
            .update_token(
                session.id,
                &token_hash,
                &token_digest,
                expires_at,
                user_agent.as_deref(),
                ip_address.as_deref(),
            )
            .await
            .map_err(ServiceError::from)?;
        if !updated {
            return Err(ServiceError::Unauthorized);
        }

        let access = self
            .auth
            .issue_session(session.user_id, session.workspace_id, Some(session.id))
            .map_err(ServiceError::from)?;

        Ok(IssuedSessionBundle {
            access,
            refresh_token,
            refresh_expires_at: expires_at,
            session,
        })
    }

    pub async fn revoke_by_token(&self, token: &str) -> Result<(), ServiceError> {
        let digest = compute_digest(token);
        self.repo
            .revoke_by_digest(&digest)
            .await
            .map_err(ServiceError::from)?;
        Ok(())
    }

    pub async fn revoke_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
    ) -> Result<bool, ServiceError> {
        let record = self
            .repo
            .find_by_id(session_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        if record.user_id != user_id {
            return Err(ServiceError::Forbidden);
        }
        self.repo
            .revoke(session_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<(), ServiceError> {
        self.repo
            .revoke_all_for_user(user_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn list_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<UserSessionRecord>, ServiceError> {
        self.repo
            .list_for_user(user_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn find_session_by_token(
        &self,
        token: &str,
    ) -> Result<Option<UserSessionRecord>, ServiceError> {
        let digest = compute_digest(token);
        Ok(self
            .repo
            .find_by_digest(&digest)
            .await
            .map_err(ServiceError::from)?
            .map(|secret| secret.session))
    }
}
