use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

#[derive(Debug, Clone)]
pub struct CommentThreadRecord {
    pub id: Uuid,
    pub document_id: Uuid,
    pub marker: String,
    pub quote: String,
    pub start_line_number: Option<i32>,
    pub start_column: Option<i32>,
    pub end_line_number: Option<i32>,
    pub end_column: Option<i32>,
    pub start_offset: Option<i32>,
    pub end_offset: Option<i32>,
    pub anchored: bool,
    pub tags: Vec<String>,
    pub created_by: Option<Uuid>,
    pub created_by_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct CommentReplyRecord {
    pub id: Uuid,
    pub thread_id: Uuid,
    pub document_id: Uuid,
    pub body: String,
    pub created_by: Option<Uuid>,
    pub created_by_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CommentThreadWithReplies {
    pub thread: CommentThreadRecord,
    pub replies: Vec<CommentReplyRecord>,
}

#[derive(Debug, Clone)]
pub struct NewCommentThread {
    pub id: Uuid,
    pub document_id: Uuid,
    pub workspace_id: Uuid,
    pub marker: String,
    pub quote: String,
    pub start_line_number: Option<i32>,
    pub start_column: Option<i32>,
    pub end_line_number: Option<i32>,
    pub end_column: Option<i32>,
    pub start_offset: Option<i32>,
    pub end_offset: Option<i32>,
    pub anchored: bool,
    pub tags: Vec<String>,
    pub created_by: Option<Uuid>,
    pub created_by_name: Option<String>,
    pub reply_id: Uuid,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct NewCommentReply {
    pub id: Uuid,
    pub thread_id: Uuid,
    pub document_id: Uuid,
    pub body: String,
    pub created_by: Option<Uuid>,
    pub created_by_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CommentThreadUpdate {
    pub workspace_id: Uuid,
    pub document_id: Uuid,
    pub thread_id: Uuid,
    pub marker: Option<String>,
    pub resolved: Option<bool>,
    pub resolved_by: Option<Uuid>,
    pub tags: Option<Vec<String>>,
    pub anchored: Option<bool>,
}

#[async_trait]
pub trait CommentRepository: Send + Sync {
    async fn list_threads(
        &self,
        workspace_id: Uuid,
        document_id: Uuid,
    ) -> PortResult<Vec<CommentThreadWithReplies>>;

    async fn create_thread(&self, input: NewCommentThread) -> PortResult<CommentThreadWithReplies>;

    async fn add_reply(&self, input: NewCommentReply) -> PortResult<Option<CommentReplyRecord>>;

    async fn update_thread(
        &self,
        input: CommentThreadUpdate,
    ) -> PortResult<Option<CommentThreadWithReplies>>;
}
