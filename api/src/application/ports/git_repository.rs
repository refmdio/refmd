use async_trait::async_trait;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct UserGitCfg {
    pub repository_url: String,
    pub branch_name: String,
    pub auth_type: Option<String>,
    pub auth_data: Option<serde_json::Value>,
    pub auto_sync: bool,
}

#[async_trait]
pub trait GitRepository: Send + Sync {
    async fn get_config(
        &self,
        user_id: Uuid,
    ) -> anyhow::Result<
        Option<(
            Uuid,
            String,
            String,
            String,
            bool,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        )>,
    >;
    async fn upsert_config(
        &self,
        user_id: Uuid,
        repository_url: &str,
        branch_name: Option<&str>,
        auth_type: &str,
        auth_data: &serde_json::Value,
        auto_sync: Option<bool>,
    ) -> anyhow::Result<(
        Uuid,
        String,
        String,
        String,
        bool,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    )>;
    async fn delete_config(&self, user_id: Uuid) -> anyhow::Result<bool>;
    async fn load_user_git_cfg(&self, user_id: Uuid) -> anyhow::Result<Option<UserGitCfg>>;
    async fn get_last_sync_log(
        &self,
        user_id: Uuid,
    ) -> anyhow::Result<
        Option<(
            Option<chrono::DateTime<chrono::Utc>>,
            Option<String>,
            Option<String>,
            Option<String>,
        )>,
    >;
    async fn log_sync_operation(
        &self,
        user_id: Uuid,
        operation: &str,
        status: &str,
        message: Option<&str>,
        commit_hash: Option<&str>,
    ) -> anyhow::Result<()>;
}
