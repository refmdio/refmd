use async_trait::async_trait;

use crate::core::ports::errors::PortResult;

#[async_trait]
pub trait GitignorePort: Send + Sync {
    async fn ensure_gitignore(&self, dir: &str) -> PortResult<bool>;
    async fn upsert_gitignore_patterns(&self, dir: &str, patterns: &[String]) -> PortResult<usize>;
    async fn read_gitignore_patterns(&self, dir: &str) -> PortResult<Vec<String>>;
}
