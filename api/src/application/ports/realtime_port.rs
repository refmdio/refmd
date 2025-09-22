use async_trait::async_trait;
use std::fmt;

#[derive(Debug)]
pub struct RealtimeError(Box<dyn std::error::Error + Send + Sync + 'static>);

impl RealtimeError {
    pub fn new<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self(Box::new(err))
    }
}

impl fmt::Display for RealtimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for RealtimeError {}

#[async_trait]
pub trait RealtimePort: Send + Sync {
    async fn get_content(&self, doc_id: &str) -> anyhow::Result<Option<String>>;
    async fn force_save_to_fs(&self, doc_id: &str) -> anyhow::Result<()>;
}
