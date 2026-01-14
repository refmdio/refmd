#[derive(Debug, Clone)]
pub struct GitConfigDto {
    pub id: uuid::Uuid,
    pub repository_url: String,
    pub branch_name: String,
    pub auth_type: String,
    pub auto_sync: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// E2EE encrypted auth data (only present for E2EE clients)
    pub encrypted_auth_data: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct GitRemoteCheckDto {
    pub ok: bool,
    pub message: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpsertGitConfigInput {
    pub repository_url: String,
    pub branch_name: Option<String>,
    pub auth_type: String,
    pub auth_data: serde_json::Value,
    pub auto_sync: Option<bool>,
}
