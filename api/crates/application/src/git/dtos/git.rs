#[derive(Debug, Clone)]
pub struct GitConfigDto {
    pub id: uuid::Uuid,
    pub repository_url: String,
    pub branch_name: String,
    pub auth_type: String,
    pub auto_sync: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct GitRemoteCheckDto {
    pub ok: bool,
    pub message: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GitStatusDto {
    pub repository_initialized: bool,
    pub has_remote: bool,
    pub current_branch: Option<String>,
    pub uncommitted_changes: u32,
    pub untracked_files: u32,
    pub last_sync: Option<chrono::DateTime<chrono::Utc>>,
    pub last_sync_status: Option<String>,
    pub last_sync_message: Option<String>,
    pub last_sync_commit_hash: Option<String>,
    pub sync_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct UpsertGitConfigInput {
    pub repository_url: String,
    pub branch_name: Option<String>,
    pub auth_type: String,
    pub auth_data: serde_json::Value,
    pub auto_sync: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct GitChangeItem {
    pub path: String,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct GitCommitInfo {
    pub hash: String,
    pub message: String,
    pub author_name: String,
    pub author_email: String,
    pub time: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct GitWorkspaceStatus {
    pub repository_initialized: bool,
    pub current_branch: Option<String>,
    pub uncommitted_changes: u32,
    pub untracked_files: u32,
}

#[derive(Debug, Clone)]
pub struct GitSyncRequestDto {
    pub message: Option<String>,
    pub force: Option<bool>,
    pub full_scan: Option<bool>,
    pub skip_push: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct GitSyncResponseDto {
    pub success: bool,
    pub message: String,
    pub commit_hash: Option<String>,
    pub files_changed: u32,
}

#[derive(Debug, Clone)]
pub struct GitSyncOutcome {
    pub files_changed: u32,
    pub commit_hash: Option<String>,
    pub pushed: bool,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct GitImportOutcome {
    pub files_changed: u32,
    pub commit_hash: Option<String>,
    pub docs_created: u32,
    pub attachments_created: u32,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct GitignoreUpdateDto {
    pub added: usize,
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GitPullResolutionDto {
    pub path: String,
    /// one of: ours, theirs, custom_text
    pub choice: String,
    pub content: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GitPullRequestDto {
    pub resolutions: Vec<GitPullResolutionDto>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GitPullConflictItemDto {
    pub path: String,
    pub is_binary: bool,
    pub ours: Option<String>,
    pub theirs: Option<String>,
    pub base: Option<String>,
    pub document_id: Option<uuid::Uuid>,
}

#[derive(Debug, Clone)]
pub struct GitPullResultDto {
    pub success: bool,
    pub message: String,
    pub files_changed: u32,
    pub commit_hash: Option<String>,
    pub conflicts: Option<Vec<GitPullConflictItemDto>>,
    pub base_commit: Option<Vec<u8>>,
    pub remote_commit: Option<Vec<u8>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GitPullSessionDto {
    pub id: uuid::Uuid,
    pub workspace_id: uuid::Uuid,
    pub status: domain::git::pull_session::GitPullSessionStatus,
    pub conflicts: Vec<GitPullConflictItemDto>,
    pub resolutions: Vec<GitPullResolutionDto>,
    pub message: Option<String>,
    pub base_commit: Option<Vec<u8>>,
    pub remote_commit: Option<Vec<u8>>,
}
