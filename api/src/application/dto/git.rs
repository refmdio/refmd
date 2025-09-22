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

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum DiffLineType {
    Added,
    Deleted,
    Context,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiffLine {
    pub line_type: DiffLineType,
    pub old_line_number: Option<u32>,
    pub new_line_number: Option<u32>,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiffResult {
    pub file_path: String,
    pub diff_lines: Vec<DiffLine>,
    pub old_content: Option<String>,
    pub new_content: Option<String>,
}
