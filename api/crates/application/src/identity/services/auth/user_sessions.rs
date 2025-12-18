use std::sync::Arc;

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use chrono::{DateTime, Duration, Utc};
use rand::{Rng, distributions::Alphanumeric, rngs::OsRng};
use uuid::Uuid;

use crate::core::services::errors::ServiceError;
use crate::identity::ports::user_session_repository::{UserSessionRecord, UserSessionRepository};
use crate::identity::services::api_tokens::{compute_digest, verify_token};
use crate::identity::services::auth::service::{AuthService, IssuedSession};

pub struct SessionMetadata<'a> {
    pub user_agent: Option<&'a str>,
    pub ip_address: Option<&'a str>,
}

#[derive(Clone)]
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
            if s.chars().count() <= max_len {
                return s.to_string();
            }
            s.chars().take(max_len).collect::<String>()
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

        let mut session = secret.session;
        if let Some(workspace_id) = workspace_override {
            session.workspace_id = workspace_id;
        }

        let remember_me = session.remember_me;
        let ttl = self.ttl_for(remember_me);
        let expires_at = now + ttl;
        let (refresh_token, token_hash, token_digest) =
            Self::generate_refresh_token().map_err(ServiceError::Unexpected)?;
        let (user_agent, ip_address) = self.metadata(&meta);

        session.expires_at = expires_at;
        session.last_seen_at = now;
        session.user_agent = user_agent.clone();
        session.ip_address = ip_address.clone();

        let updated = self
            .repo
            .update_token(
                session.id,
                &secret.token_digest,
                &token_hash,
                &token_digest,
                expires_at,
                user_agent.as_deref(),
                ip_address.as_deref(),
                workspace_override,
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

    pub async fn ensure_session_active(&self, session_id: Uuid) -> Result<(), ServiceError> {
        let record = self
            .repo
            .find_by_id(session_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::Unauthorized)?;
        let now = Utc::now();
        if record.revoked_at.is_some() || record.expires_at <= now {
            let _ = self.repo.revoke(session_id).await;
            return Err(ServiceError::Unauthorized);
        }
        self.repo
            .touch(session_id)
            .await
            .map_err(ServiceError::from)?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ports::api_token_repository::{
        ApiToken, ApiTokenRepository, ApiTokenSecret,
    };
    use crate::identity::ports::user_session_repository::{
        UserSessionRepository, UserSessionSecret,
    };
    use crate::identity::services::auth::token_validation::TokenValidationService;
    use anyhow::bail;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[derive(Default)]
    struct InMemorySessionRepo {
        sessions: Mutex<HashMap<Uuid, SessionEntry>>,
        digests: Mutex<HashMap<String, Uuid>>,
    }

    struct SessionEntry {
        record: UserSessionRecord,
        token_hash: String,
        token_digest: String,
    }

    impl SessionEntry {
        fn secret(&self) -> UserSessionSecret {
            UserSessionSecret {
                session: self.record.clone(),
                token_hash: self.token_hash.clone(),
                token_digest: self.token_digest.clone(),
            }
        }
    }

    #[async_trait]
    impl UserSessionRepository for InMemorySessionRepo {
        async fn create(
            &self,
            user_id: Uuid,
            workspace_id: Uuid,
            token_hash: &str,
            token_digest: &str,
            expires_at: DateTime<Utc>,
            remember_me: bool,
            user_agent: Option<&str>,
            ip_address: Option<&str>,
        ) -> anyhow::Result<UserSessionRecord> {
            let mut sessions = self.sessions.lock().await;
            let mut digests = self.digests.lock().await;
            let id = Uuid::new_v4();
            let now = Utc::now();
            let record = UserSessionRecord {
                id,
                user_id,
                workspace_id,
                user_agent: user_agent.map(|s| s.to_string()),
                ip_address: ip_address.map(|s| s.to_string()),
                remember_me,
                created_at: now,
                last_seen_at: now,
                expires_at,
                revoked_at: None,
            };
            sessions.insert(
                id,
                SessionEntry {
                    record: record.clone(),
                    token_hash: token_hash.to_string(),
                    token_digest: token_digest.to_string(),
                },
            );
            digests.insert(token_digest.to_string(), id);
            Ok(record)
        }

        async fn find_by_digest(
            &self,
            token_digest: &str,
        ) -> anyhow::Result<Option<UserSessionSecret>> {
            let digests = self.digests.lock().await;
            let sessions = self.sessions.lock().await;
            Ok(digests
                .get(token_digest)
                .and_then(|id| sessions.get(id))
                .map(|entry| entry.secret()))
        }

        async fn update_token(
            &self,
            session_id: Uuid,
            expected_token_digest: &str,
            token_hash: &str,
            token_digest: &str,
            expires_at: DateTime<Utc>,
            user_agent: Option<&str>,
            ip_address: Option<&str>,
            workspace_id: Option<Uuid>,
        ) -> anyhow::Result<bool> {
            let mut sessions = self.sessions.lock().await;
            let mut digests = self.digests.lock().await;
            let Some(entry) = sessions.get_mut(&session_id) else {
                return Ok(false);
            };
            if entry.record.revoked_at.is_some() {
                return Ok(false);
            }
            if entry.token_digest != expected_token_digest {
                return Ok(false);
            }
            digests.retain(|_, id| id != &session_id);
            entry.token_hash = token_hash.to_string();
            entry.token_digest = token_digest.to_string();
            entry.record.expires_at = expires_at;
            entry.record.last_seen_at = Utc::now();
            entry.record.user_agent = user_agent.map(|s| s.to_string());
            entry.record.ip_address = ip_address.map(|s| s.to_string());
            if let Some(ws) = workspace_id {
                entry.record.workspace_id = ws;
            }
            digests.insert(token_digest.to_string(), session_id);
            Ok(true)
        }

        async fn update_workspace(
            &self,
            session_id: Uuid,
            workspace_id: Uuid,
        ) -> anyhow::Result<bool> {
            let mut sessions = self.sessions.lock().await;
            if let Some(entry) = sessions.get_mut(&session_id) {
                if entry.record.revoked_at.is_none() {
                    entry.record.workspace_id = workspace_id;
                    return Ok(true);
                }
            }
            Ok(false)
        }

        async fn touch(&self, session_id: Uuid) -> anyhow::Result<()> {
            if let Some(entry) = self.sessions.lock().await.get_mut(&session_id) {
                entry.record.last_seen_at = Utc::now();
            }
            Ok(())
        }

        async fn list_for_user(&self, user_id: Uuid) -> anyhow::Result<Vec<UserSessionRecord>> {
            let sessions = self.sessions.lock().await;
            Ok(sessions
                .values()
                .filter(|entry| entry.record.user_id == user_id)
                .map(|entry| entry.record.clone())
                .collect())
        }

        async fn find_by_id(&self, session_id: Uuid) -> anyhow::Result<Option<UserSessionRecord>> {
            Ok(self
                .sessions
                .lock()
                .await
                .get(&session_id)
                .map(|entry| entry.record.clone()))
        }

        async fn revoke(&self, session_id: Uuid) -> anyhow::Result<bool> {
            let mut sessions = self.sessions.lock().await;
            if let Some(entry) = sessions.get_mut(&session_id) {
                if entry.record.revoked_at.is_none() {
                    entry.record.revoked_at = Some(Utc::now());
                    return Ok(true);
                }
            }
            Ok(false)
        }

        async fn revoke_by_digest(&self, token_digest: &str) -> anyhow::Result<bool> {
            let id = {
                let digests = self.digests.lock().await;
                digests.get(token_digest).cloned()
            };
            if let Some(session_id) = id {
                return self.revoke(session_id).await;
            }
            Ok(false)
        }

        async fn revoke_all_for_user(&self, user_id: Uuid) -> anyhow::Result<()> {
            let mut sessions = self.sessions.lock().await;
            for entry in sessions
                .values_mut()
                .filter(|entry| entry.record.user_id == user_id)
            {
                entry.record.revoked_at = Some(Utc::now());
            }
            Ok(())
        }

        async fn delete_expired(
            &self,
            before: DateTime<Utc>,
            batch_size: i64,
        ) -> anyhow::Result<u64> {
            let mut sessions = self.sessions.lock().await;
            let mut digests = self.digests.lock().await;
            let mut removed = 0u64;
            let ids: Vec<Uuid> = sessions
                .iter()
                .filter(|(_, entry)| entry.record.expires_at < before)
                .map(|(id, _)| *id)
                .take(batch_size as usize)
                .collect();
            for id in ids {
                if let Some(entry) = sessions.remove(&id) {
                    digests.retain(|_, digest_id| *digest_id != id);
                    removed += 1;
                    drop(entry);
                }
            }
            Ok(removed)
        }
    }

    struct NoopApiTokenRepo;

    #[async_trait]
    impl ApiTokenRepository for NoopApiTokenRepo {
        async fn create(
            &self,
            _workspace_id: Uuid,
            _owner_id: Uuid,
            _name: &str,
            _token_hash: &str,
            _token_digest: &str,
        ) -> anyhow::Result<ApiToken> {
            bail!("not implemented")
        }

        async fn list_active(&self, _workspace_id: Uuid) -> anyhow::Result<Vec<ApiToken>> {
            bail!("not implemented")
        }

        async fn revoke(&self, _workspace_id: Uuid, _token_id: Uuid) -> anyhow::Result<bool> {
            bail!("not implemented")
        }

        async fn find_by_digest(&self, _digest: &str) -> anyhow::Result<Option<ApiTokenSecret>> {
            Ok(None)
        }

        async fn touch_last_used(&self, _token_id: Uuid) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn build_service() -> UserSessionService {
        let repo = Arc::new(InMemorySessionRepo::default());
        let token_validation = Arc::new(TokenValidationService::new(Arc::new(NoopApiTokenRepo)));
        let auth = Arc::new(AuthService::new("secret", token_validation, 60));
        UserSessionService::new(repo, auth, 120, 600)
    }

    #[tokio::test]
    async fn issue_and_refresh_session_updates_state() {
        let service = build_service();
        let user_id = Uuid::new_v4();
        let workspace_a = Uuid::new_v4();
        let workspace_b = Uuid::new_v4();
        let issued = service
            .issue_new_session(
                user_id,
                workspace_a,
                false,
                SessionMetadata {
                    user_agent: Some(&"a".repeat(600)),
                    ip_address: Some("10.0.0.1"),
                },
            )
            .await
            .expect("issue session");
        assert_eq!(issued.session.workspace_id, workspace_a);
        assert!(issued.session.user_agent.as_ref().unwrap().len() <= 500);

        let refreshed = service
            .refresh_session(
                &issued.refresh_token,
                Some(workspace_b),
                SessionMetadata {
                    user_agent: Some("Mozilla/5.0"),
                    ip_address: Some("127.0.0.1"),
                },
            )
            .await
            .expect("refresh session");
        assert_eq!(refreshed.session.workspace_id, workspace_b);
        assert_ne!(refreshed.refresh_token, issued.refresh_token);
        assert_eq!(refreshed.session.user_agent.as_deref(), Some("Mozilla/5.0"));
    }

    #[tokio::test]
    async fn concurrent_refresh_allows_only_one_success() {
        let service = build_service();
        let user_id = Uuid::new_v4();
        let workspace = Uuid::new_v4();
        let issued = service
            .issue_new_session(
                user_id,
                workspace,
                true,
                SessionMetadata {
                    user_agent: Some("ua0"),
                    ip_address: Some("10.0.0.1"),
                },
            )
            .await
            .expect("issue session");

        let fut1 = service.refresh_session(
            &issued.refresh_token,
            None,
            SessionMetadata {
                user_agent: Some("ua1"),
                ip_address: Some("10.0.0.2"),
            },
        );
        let fut2 = service.refresh_session(
            &issued.refresh_token,
            None,
            SessionMetadata {
                user_agent: Some("ua2"),
                ip_address: Some("10.0.0.3"),
            },
        );

        let (res1, res2) = tokio::join!(fut1, fut2);
        let (refreshed, err) = match (res1, res2) {
            (Ok(bundle), Err(err)) => (bundle, err),
            (Err(err), Ok(bundle)) => (bundle, err),
            (Ok(_), Ok(_)) => panic!("both refreshes succeeded unexpectedly"),
            (Err(e1), Err(e2)) => {
                panic!("both refreshes failed unexpectedly: {e1:?} / {e2:?}")
            }
        };

        assert!(matches!(err, ServiceError::Unauthorized));
        assert_ne!(refreshed.refresh_token, issued.refresh_token);

        // New refresh token should continue to work normally.
        let refreshed3 = service
            .refresh_session(
                &refreshed.refresh_token,
                None,
                SessionMetadata {
                    user_agent: Some("ua3"),
                    ip_address: Some("10.0.0.4"),
                },
            )
            .await
            .expect("refresh3");
        assert_ne!(refreshed3.refresh_token, refreshed.refresh_token);
    }

    #[tokio::test]
    async fn revoke_session_requires_owner() {
        let service = build_service();
        let owner = Uuid::new_v4();
        let intruder = Uuid::new_v4();
        let workspace = Uuid::new_v4();
        let issued = service
            .issue_new_session(
                owner,
                workspace,
                false,
                SessionMetadata {
                    user_agent: None,
                    ip_address: None,
                },
            )
            .await
            .expect("issue session");
        let err = service
            .revoke_session(intruder, issued.session.id)
            .await
            .expect_err("should be forbidden");
        assert!(matches!(err, ServiceError::Forbidden));
        let revoked = service
            .revoke_session(owner, issued.session.id)
            .await
            .expect("owner can revoke");
        assert!(revoked);
    }

    #[tokio::test]
    async fn ensure_session_active_allows_valid_session() {
        let service = build_service();
        let user_id = Uuid::new_v4();
        let workspace = Uuid::new_v4();
        let issued = service
            .issue_new_session(
                user_id,
                workspace,
                false,
                SessionMetadata {
                    user_agent: None,
                    ip_address: None,
                },
            )
            .await
            .expect("issue session");
        service
            .ensure_session_active(issued.session.id)
            .await
            .expect("session should be active");
    }

    #[tokio::test]
    async fn ensure_session_active_rejects_revoked_session() {
        let service = build_service();
        let user_id = Uuid::new_v4();
        let workspace = Uuid::new_v4();
        let issued = service
            .issue_new_session(
                user_id,
                workspace,
                false,
                SessionMetadata {
                    user_agent: None,
                    ip_address: None,
                },
            )
            .await
            .expect("issue session");
        service
            .revoke_session(user_id, issued.session.id)
            .await
            .expect("revoke session");
        let err = service
            .ensure_session_active(issued.session.id)
            .await
            .expect_err("session should be invalid");
        assert!(matches!(err, ServiceError::Unauthorized));
    }
}
