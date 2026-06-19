use uuid::Uuid;

use crate::documents::doc_type::DocumentType;
use crate::documents::path::{DesiredPath, Slug};
use crate::documents::title::Title;

#[derive(Debug, Clone)]
pub struct Document {
    id: Uuid,
    owner_user_id: Option<Uuid>,
    workspace_id: Uuid,
    title: Title,
    parent_id: Option<Uuid>,
    doc_type: DocumentType,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    created_by_plugin: Option<String>,
    slug: Slug,
    desired_path: DesiredPath,
    path: Option<String>,
    created_by: Option<Uuid>,
    archived_at: Option<chrono::DateTime<chrono::Utc>>,
    archived_by: Option<Uuid>,
    archived_parent_id: Option<Uuid>,
}

impl Document {
    #[allow(clippy::too_many_arguments)]
    pub fn rehydrate(
        id: Uuid,
        owner_user_id: Option<Uuid>,
        workspace_id: Uuid,
        title: Title,
        parent_id: Option<Uuid>,
        doc_type: DocumentType,
        created_at: chrono::DateTime<chrono::Utc>,
        updated_at: chrono::DateTime<chrono::Utc>,
        created_by_plugin: Option<String>,
        slug: Slug,
        desired_path: DesiredPath,
        path: Option<String>,
        created_by: Option<Uuid>,
        archived_at: Option<chrono::DateTime<chrono::Utc>>,
        archived_by: Option<Uuid>,
        archived_parent_id: Option<Uuid>,
    ) -> Self {
        Self {
            id,
            owner_user_id,
            workspace_id,
            title,
            parent_id,
            doc_type,
            created_at,
            updated_at,
            created_by_plugin,
            slug,
            desired_path,
            path,
            created_by,
            archived_at,
            archived_by,
            archived_parent_id,
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn owner_user_id(&self) -> Option<Uuid> {
        self.owner_user_id
    }

    pub fn workspace_id(&self) -> Uuid {
        self.workspace_id
    }

    pub fn title(&self) -> &Title {
        &self.title
    }

    pub fn parent_id(&self) -> Option<Uuid> {
        self.parent_id
    }

    pub fn doc_type(&self) -> DocumentType {
        self.doc_type
    }

    pub fn created_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.created_at
    }

    pub fn updated_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.updated_at
    }

    pub fn created_by_plugin(&self) -> Option<&str> {
        self.created_by_plugin.as_deref()
    }

    pub fn slug(&self) -> &Slug {
        &self.slug
    }

    pub fn desired_path(&self) -> &DesiredPath {
        &self.desired_path
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn created_by(&self) -> Option<Uuid> {
        self.created_by
    }

    pub fn archived_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.archived_at
    }

    pub fn archived_by(&self) -> Option<Uuid> {
        self.archived_by
    }

    pub fn archived_parent_id(&self) -> Option<Uuid> {
        self.archived_parent_id
    }
}

#[derive(Debug, Clone)]
pub struct SearchHit {
    pub id: Uuid,
    pub title: Title,
    pub doc_type: DocumentType,
    pub path: Option<String>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct BacklinkInfo {
    pub document_id: Uuid,
    pub title: Title,
    pub document_type: DocumentType,
    pub file_path: Option<String>,
    pub link_type: String,
    pub link_text: Option<String>,
    pub link_count: i64,
}

#[derive(Debug, Clone)]
pub struct OutgoingLink {
    pub document_id: Uuid,
    pub title: Title,
    pub document_type: DocumentType,
    pub file_path: Option<String>,
    pub link_type: String,
    pub link_text: Option<String>,
    pub position_start: Option<i32>,
    pub position_end: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct DocumentCommentReply {
    pub id: Uuid,
    pub thread_id: Uuid,
    pub document_id: Uuid,
    pub body: String,
    pub created_by: Option<Uuid>,
    pub created_by_name: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct DocumentCommentThread {
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
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,
    pub resolved_by: Option<Uuid>,
    pub replies: Vec<DocumentCommentReply>,
}
