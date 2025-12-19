use std::fmt;
use std::ops::Deref;

#[derive(Debug)]
pub struct PortError(anyhow::Error);

impl PortError {
    pub fn into_anyhow(self) -> anyhow::Error {
        self.0
    }
}

impl Deref for PortError {
    type Target = anyhow::Error;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<anyhow::Error> for PortError {
    fn from(err: anyhow::Error) -> Self {
        Self(err)
    }
}

impl fmt::Display for PortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub type PortResult<T> = Result<T, PortError>;

impl From<PortError> for anyhow::Error {
    fn from(err: PortError) -> Self {
        err.into_anyhow()
    }
}
