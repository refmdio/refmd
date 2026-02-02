//! Register user command

use std::sync::Arc;
use domain::identity::{Email, EmailError, User, UserRepository, UserSettings, UserSettingsRepository};
use thiserror::Error;

/// Register user command
#[derive(Debug)]
pub struct RegisterUserCommand {
    pub email: String,
    pub name: String,
}

/// Register user result
#[derive(Debug)]
pub struct RegisterUserResult {
    pub user: User,
    pub settings: UserSettings,
}

/// Register user error
#[derive(Debug, Error)]
pub enum RegisterUserError<R: std::error::Error, S: std::error::Error> {
    #[error("invalid email: {0}")]
    InvalidEmail(#[from] EmailError),

    #[error("email already exists")]
    EmailAlreadyExists,

    #[error("user repository error: {0}")]
    UserRepository(R),

    #[error("settings repository error: {0}")]
    SettingsRepository(S),
}

impl<R: std::error::Error, S: std::error::Error> RegisterUserError<R, S> {
    /// Returns true if this is a conflict error (email already exists)
    pub fn is_conflict(&self) -> bool {
        matches!(self, RegisterUserError::EmailAlreadyExists)
    }

    /// Returns true if this is a bad request error (invalid input)
    pub fn is_bad_request(&self) -> bool {
        matches!(self, RegisterUserError::InvalidEmail(_))
    }
}

/// Register user handler
pub struct RegisterUserHandler<U, S> {
    user_repo: Arc<U>,
    settings_repo: Arc<S>,
}

impl<U, S> RegisterUserHandler<U, S>
where
    U: UserRepository,
    S: UserSettingsRepository,
{
    pub fn new(user_repo: Arc<U>, settings_repo: Arc<S>) -> Self {
        Self {
            user_repo,
            settings_repo,
        }
    }

    pub async fn handle(
        &self,
        command: RegisterUserCommand,
    ) -> Result<RegisterUserResult, RegisterUserError<U::Error, S::Error>> {
        // Validate email
        let email = Email::new(&command.email)?;

        // Check if email already exists
        if self
            .user_repo
            .email_exists(&email)
            .await
            .map_err(RegisterUserError::UserRepository)?
        {
            return Err(RegisterUserError::EmailAlreadyExists);
        }

        // Create user
        let user = User::new(email, command.name);

        // Save user
        self.user_repo
            .save(&user)
            .await
            .map_err(RegisterUserError::UserRepository)?;

        // Create default settings
        let settings = UserSettings::new(user.id);

        // Save settings
        self.settings_repo
            .save(&settings)
            .await
            .map_err(RegisterUserError::SettingsRepository)?;

        Ok(RegisterUserResult { user, settings })
    }
}
