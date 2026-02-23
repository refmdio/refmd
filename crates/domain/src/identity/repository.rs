//! Identity repository traits

use async_trait::async_trait;

use super::session::{Session, SessionId};
use super::user::{User, UserId};
use super::user_settings::UserSettings;
use super::value_objects::Email;

/// User repository trait
#[async_trait]
pub trait UserRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find user by ID
    async fn find_by_id(&self, id: UserId) -> Result<Option<User>, Self::Error>;

    /// Find users by IDs (batch)
    async fn find_by_ids(&self, ids: &[UserId]) -> Result<Vec<User>, Self::Error>;

    /// Find user by email
    async fn find_by_email(&self, email: &Email) -> Result<Option<User>, Self::Error>;

    /// Check if email exists
    async fn email_exists(&self, email: &Email) -> Result<bool, Self::Error>;

    /// Save user (insert or update)
    async fn save(&self, user: &User) -> Result<(), Self::Error>;

    /// Delete user
    async fn delete(&self, id: UserId) -> Result<(), Self::Error>;
}

/// Session repository trait
#[async_trait]
pub trait SessionRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find session by ID
    async fn find_by_id(&self, id: SessionId) -> Result<Option<Session>, Self::Error>;

    /// Find session by token hash
    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<Session>, Self::Error>;

    /// Find all sessions for a user
    async fn find_by_user_id(&self, user_id: UserId) -> Result<Vec<Session>, Self::Error>;

    /// Save session
    async fn save(&self, session: &Session) -> Result<(), Self::Error>;

    /// Delete session
    async fn delete(&self, id: SessionId) -> Result<(), Self::Error>;

    /// Delete all sessions for a user
    async fn delete_by_user_id(&self, user_id: UserId) -> Result<(), Self::Error>;
}

/// UserSettings repository trait
#[async_trait]
pub trait UserSettingsRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find settings by user ID
    async fn find_by_user_id(&self, user_id: UserId) -> Result<Option<UserSettings>, Self::Error>;

    /// Save settings (insert or update)
    async fn save(&self, settings: &UserSettings) -> Result<(), Self::Error>;

    /// Delete settings
    async fn delete(&self, user_id: UserId) -> Result<(), Self::Error>;
}
