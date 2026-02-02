//! Get user query

use domain::identity::{User, UserId, UserRepository};
use std::sync::Arc;
use thiserror::Error;

/// Get user query
#[derive(Debug)]
pub struct GetUserQuery {
    pub user_id: UserId,
}

/// Get user error
#[derive(Debug, Error)]
pub enum GetUserError<R: std::error::Error> {
    #[error("user not found")]
    NotFound,

    #[error("repository error: {0}")]
    Repository(R),
}

/// Get user handler
pub struct GetUserHandler<R> {
    user_repo: Arc<R>,
}

impl<R> GetUserHandler<R>
where
    R: UserRepository,
{
    pub fn new(user_repo: Arc<R>) -> Self {
        Self { user_repo }
    }

    pub async fn handle(&self, query: GetUserQuery) -> Result<User, GetUserError<R::Error>> {
        self.user_repo
            .find_by_id(query.user_id)
            .await
            .map_err(GetUserError::Repository)?
            .ok_or(GetUserError::NotFound)
    }
}
