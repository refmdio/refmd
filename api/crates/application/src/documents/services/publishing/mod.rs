use std::sync::Arc;

use uuid::Uuid;

use crate::core::services::errors::ServiceError;
use crate::documents::comment_markers::strip_comment_markers;
use crate::documents::dtos::PublicDocumentSummaryDto;
use crate::documents::ports::comment_repository::CommentRepository;
use crate::documents::ports::publishing::public_repository::PublicRepository;
use crate::documents::ports::realtime::realtime_port::RealtimeEngine;
use crate::documents::use_cases::publishing::get_public::GetPublicByWorkspaceAndId;
use crate::documents::use_cases::publishing::get_status::{GetPublishStatus, PublishStatusDto};
use crate::documents::use_cases::publishing::list_workspace::ListWorkspacePublic;
use crate::documents::use_cases::publishing::publish::{PublishDocument, PublishResponseDto};
use crate::documents::use_cases::publishing::unpublish::UnpublishDocument;
use async_trait::async_trait;
use domain::access::permissions::PermissionSet;
use domain::documents::document::Document;
use domain::documents::public_policy;

pub struct PublicService {
    repo: Arc<dyn PublicRepository>,
    realtime: Arc<dyn RealtimeEngine>,
    comments: Arc<dyn CommentRepository>,
}

#[async_trait]
pub trait PublicServiceFacade: Send + Sync {
    async fn publish_document(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<PublishResponseDto, ServiceError>;

    async fn unpublish_document(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<bool, ServiceError>;

    async fn get_publish_status(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<PublishResponseDto, ServiceError>;

    async fn list_workspace_public_documents(
        &self,
        workspace_slug: &str,
    ) -> Result<Vec<PublicDocumentSummaryDto>, ServiceError>;

    async fn get_public_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> Result<Document, ServiceError>;

    async fn get_public_content_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> Result<String, ServiceError>;
}

#[async_trait]
impl PublicServiceFacade for PublicService {
    async fn publish_document(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<PublishResponseDto, ServiceError> {
        self.publish_document(workspace_id, permissions, doc_id)
            .await
    }

    async fn unpublish_document(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<bool, ServiceError> {
        self.unpublish_document(workspace_id, permissions, doc_id)
            .await
    }

    async fn get_publish_status(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<PublishResponseDto, ServiceError> {
        self.get_publish_status(workspace_id, permissions, doc_id)
            .await
    }

    async fn list_workspace_public_documents(
        &self,
        workspace_slug: &str,
    ) -> Result<Vec<PublicDocumentSummaryDto>, ServiceError> {
        self.list_workspace_public_documents(workspace_slug).await
    }

    async fn get_public_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> Result<Document, ServiceError> {
        self.get_public_by_workspace_and_id(workspace_slug, doc_id)
            .await
    }

    async fn get_public_content_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> Result<String, ServiceError> {
        self.get_public_content_by_workspace_and_id(workspace_slug, doc_id)
            .await
    }
}

impl PublicService {
    pub fn new(
        repo: Arc<dyn PublicRepository>,
        realtime: Arc<dyn RealtimeEngine>,
        comments: Arc<dyn CommentRepository>,
    ) -> Self {
        Self {
            repo,
            realtime,
            comments,
        }
    }

    pub async fn publish_document(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<PublishResponseDto, ServiceError> {
        public_policy::ensure_public_publish_allowed(permissions)
            .map_err(|_| ServiceError::Forbidden)?;
        let uc = PublishDocument {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_id, doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)
    }

    pub async fn unpublish_document(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<bool, ServiceError> {
        public_policy::ensure_public_unpublish_allowed(permissions)
            .map_err(|_| ServiceError::Forbidden)?;
        let uc = UnpublishDocument {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_id, doc_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn get_publish_status(
        &self,
        workspace_id: Uuid,
        permissions: &PermissionSet,
        doc_id: Uuid,
    ) -> Result<PublishResponseDto, ServiceError> {
        public_policy::ensure_public_publish_allowed(permissions)
            .map_err(|_| ServiceError::Forbidden)?;
        let uc = GetPublishStatus {
            repo: self.repo.as_ref(),
        };
        let status: PublishStatusDto = uc
            .execute(workspace_id, doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        Ok(PublishResponseDto {
            slug: status.slug,
            public_url: status.public_url,
        })
    }

    pub async fn list_workspace_public_documents(
        &self,
        workspace_slug: &str,
    ) -> Result<Vec<PublicDocumentSummaryDto>, ServiceError> {
        let uc = ListWorkspacePublic {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_slug).await.map_err(ServiceError::from)
    }

    pub async fn get_public_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> Result<Document, ServiceError> {
        let uc = GetPublicByWorkspaceAndId {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_slug, doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)
    }

    pub async fn get_public_content_by_workspace_and_id(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> Result<String, ServiceError> {
        let document = self
            .repo
            .get_public_meta_by_workspace_and_id(workspace_slug, doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        let content = self
            .realtime
            .get_content(&doc_id.to_string())
            .await
            .map_err(ServiceError::from)?
            .unwrap_or_default();
        let comment_markers = self
            .comments
            .list_threads(document.workspace_id(), doc_id)
            .await
            .map_err(ServiceError::from)?
            .into_iter()
            .map(|record| record.thread.marker)
            .collect::<Vec<_>>();
        Ok(strip_comment_markers(&content, &comment_markers))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use async_trait::async_trait;
    use chrono::Utc;

    use super::*;
    use crate::core::ports::errors::PortResult;
    use crate::documents::ports::comment_repository::{
        CommentReplyRecord, CommentThreadRecord, CommentThreadUpdate, CommentThreadWithReplies,
        NewCommentReply, NewCommentThread,
    };
    use crate::documents::ports::realtime::realtime_types::{DynRealtimeSink, DynRealtimeStream};
    use domain::documents::doc_type::DocumentType;
    use domain::documents::path::{DesiredPath, Slug};
    use domain::documents::title::Title;

    struct FakePublicRepo {
        workspace_slug: String,
        document: Document,
    }

    #[async_trait]
    impl PublicRepository for FakePublicRepo {
        async fn ensure_workspace_title_and_slug(
            &self,
            _doc_id: Uuid,
            _workspace_id: Uuid,
        ) -> PortResult<
            Option<crate::documents::ports::publishing::public_repository::WorkspaceTitleAndSlug>,
        > {
            Ok(None)
        }

        async fn upsert_public_document(&self, _doc_id: Uuid, _slug: &str) -> PortResult<()> {
            Ok(())
        }

        async fn slug_exists(&self, _slug: &str) -> PortResult<bool> {
            Ok(false)
        }

        async fn is_workspace_document(
            &self,
            _doc_id: Uuid,
            _workspace_id: Uuid,
        ) -> PortResult<bool> {
            Ok(true)
        }

        async fn delete_public_document(&self, _doc_id: Uuid) -> PortResult<bool> {
            Ok(true)
        }

        async fn get_publish_status(
            &self,
            _workspace_id: Uuid,
            _doc_id: Uuid,
        ) -> PortResult<
            Option<crate::documents::ports::publishing::public_repository::PublishStatusRow>,
        > {
            Ok(None)
        }

        async fn list_workspace_public_documents(
            &self,
            _workspace_slug: &str,
        ) -> PortResult<
            Vec<crate::documents::ports::publishing::public_repository::PublicDocumentSummaryRow>,
        > {
            Ok(Vec::new())
        }

        async fn get_public_meta_by_workspace_and_id(
            &self,
            workspace_slug: &str,
            doc_id: Uuid,
        ) -> PortResult<Option<Document>> {
            if workspace_slug == self.workspace_slug && doc_id == self.document.id() {
                Ok(Some(self.document.clone()))
            } else {
                Ok(None)
            }
        }

        async fn public_exists_by_workspace_and_id(
            &self,
            workspace_slug: &str,
            doc_id: Uuid,
        ) -> PortResult<bool> {
            Ok(workspace_slug == self.workspace_slug && doc_id == self.document.id())
        }
    }

    struct FakeRealtime {
        document_id: Uuid,
        content: String,
    }

    #[async_trait]
    impl RealtimeEngine for FakeRealtime {
        async fn subscribe(
            &self,
            _doc_id: &str,
            _sink: DynRealtimeSink,
            _stream: DynRealtimeStream,
            _can_edit: bool,
        ) -> PortResult<()> {
            Ok(())
        }

        async fn get_content(&self, doc_id: &str) -> PortResult<Option<String>> {
            if doc_id == self.document_id.to_string() {
                Ok(Some(self.content.clone()))
            } else {
                Ok(None)
            }
        }

        async fn force_persist(&self, _doc_id: &str) -> PortResult<()> {
            Ok(())
        }

        async fn apply_snapshot(&self, _doc_id: &str, _snapshot: &[u8]) -> PortResult<()> {
            Ok(())
        }
    }

    struct FakeComments {
        workspace_id: Uuid,
        document_id: Uuid,
        markers: HashSet<String>,
    }

    #[async_trait]
    impl CommentRepository for FakeComments {
        async fn list_threads(
            &self,
            workspace_id: Uuid,
            document_id: Uuid,
        ) -> PortResult<Vec<CommentThreadWithReplies>> {
            if workspace_id != self.workspace_id || document_id != self.document_id {
                return Ok(Vec::new());
            }
            Ok(self
                .markers
                .iter()
                .map(|marker| CommentThreadWithReplies {
                    thread: CommentThreadRecord {
                        id: Uuid::new_v4(),
                        document_id,
                        marker: marker.clone(),
                        quote: "target".to_string(),
                        start_line_number: None,
                        start_column: None,
                        end_line_number: None,
                        end_column: None,
                        start_offset: None,
                        end_offset: None,
                        anchored: true,
                        tags: Vec::new(),
                        created_by: None,
                        created_by_name: None,
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                        resolved_at: None,
                        resolved_by: None,
                    },
                    replies: Vec::new(),
                })
                .collect())
        }

        async fn create_thread(
            &self,
            _input: NewCommentThread,
        ) -> PortResult<CommentThreadWithReplies> {
            unreachable!("not used by public content tests")
        }

        async fn add_reply(
            &self,
            _input: NewCommentReply,
        ) -> PortResult<Option<CommentReplyRecord>> {
            unreachable!("not used by public content tests")
        }

        async fn update_thread(
            &self,
            _input: CommentThreadUpdate,
        ) -> PortResult<Option<CommentThreadWithReplies>> {
            unreachable!("not used by public content tests")
        }
    }

    fn test_document(id: Uuid, workspace_id: Uuid) -> Document {
        Document::rehydrate(
            id,
            None,
            workspace_id,
            Title::new("Published"),
            None,
            DocumentType::Document,
            Utc::now(),
            Utc::now(),
            None,
            Slug::new("published").expect("valid slug"),
            DesiredPath::new("published.md").expect("valid desired path"),
            None,
            None,
            None,
            None,
            None,
        )
    }

    #[tokio::test]
    async fn public_content_strips_only_persisted_comment_markers() {
        let workspace_id = Uuid::new_v4();
        let document_id = Uuid::new_v4();
        let marker = "<!--comment:owned-->".to_string();
        let manual = "<!--comment:manual-->";
        let document = test_document(document_id, workspace_id);
        let repo = Arc::new(FakePublicRepo {
            workspace_slug: "docs".to_string(),
            document,
        });
        let realtime = Arc::new(FakeRealtime {
            document_id,
            content: format!("```md\nalpha{marker}\n{manual}\n```"),
        });
        let comments = Arc::new(FakeComments {
            workspace_id,
            document_id,
            markers: HashSet::from([marker]),
        });
        let service = PublicService::new(repo, realtime, comments);

        let content = service
            .get_public_content_by_workspace_and_id("docs", document_id)
            .await
            .expect("public content loads");

        assert_eq!(content, format!("```md\nalpha\n{manual}\n```"));
    }
}
