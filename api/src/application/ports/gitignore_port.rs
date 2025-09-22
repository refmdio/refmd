use async_trait::async_trait;

#[async_trait]
pub trait GitignorePort: Send + Sync {
    async fn ensure_gitignore(&self, dir: &str) -> anyhow::Result<bool>;
    async fn upsert_gitignore_patterns(
        &self,
        dir: &str,
        patterns: &[String],
    ) -> anyhow::Result<usize>;
    async fn read_gitignore_patterns(&self, dir: &str) -> anyhow::Result<Vec<String>>;
}
