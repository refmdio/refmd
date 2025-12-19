use anyhow::Error;
use thiserror::Error;

use crate::core::ports::errors::PortError;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("token expired")]
    TokenExpired,
    #[error("forbidden")]
    Forbidden,
    #[error("conflict")]
    Conflict,
    #[error("not found")]
    NotFound,
    #[error("bad request: {0}")]
    BadRequest(&'static str),
    #[error(transparent)]
    Unexpected(#[from] Error),
}

impl ServiceError {
    pub fn is_internal(&self) -> bool {
        matches!(self, ServiceError::Unexpected(_))
    }
}

impl From<PortError> for ServiceError {
    fn from(err: PortError) -> Self {
        ServiceError::Unexpected(err.into_anyhow())
    }
}
