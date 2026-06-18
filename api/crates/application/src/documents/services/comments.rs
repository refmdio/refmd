use uuid::Uuid;

use domain::documents::document::{
    DocumentCommentReply as DomainCommentReply, DocumentCommentThread as DomainCommentThread,
};

use crate::core::services::access::{self, Actor};
use crate::core::services::errors::ServiceError;
use crate::documents::ports::comment_repository::{
    CommentReplyRecord, CommentThreadWithReplies, NewCommentReply, NewCommentThread,
};

use super::DocumentService;

fn validate_marker(marker: &str) -> Result<(), ServiceError> {
    let marker_id = marker
        .trim_start_matches("<!--comment:")
        .trim_end_matches("-->");
    if marker.starts_with("<!--comment:")
        && marker.ends_with("-->")
        && !marker_id.is_empty()
        && marker_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Ok(());
    }
    Err(ServiceError::BadRequest("invalid_comment_marker"))
}

fn validate_body(body: &str) -> Result<(), ServiceError> {
    if body.trim().is_empty() {
        return Err(ServiceError::BadRequest("comment_body_required"));
    }
    Ok(())
}

fn actor_user_id(actor: &Actor) -> Option<Uuid> {
    match actor {
        Actor::User(user_id) => Some(*user_id),
        _ => None,
    }
}

fn to_domain_reply(reply: CommentReplyRecord) -> DomainCommentReply {
    DomainCommentReply {
        id: reply.id,
        thread_id: reply.thread_id,
        document_id: reply.document_id,
        body: reply.body,
        created_by: reply.created_by,
        created_by_name: reply.created_by_name,
        created_at: reply.created_at,
    }
}

fn to_domain_thread(record: CommentThreadWithReplies) -> DomainCommentThread {
    DomainCommentThread {
        id: record.thread.id,
        document_id: record.thread.document_id,
        marker: record.thread.marker,
        quote: record.thread.quote,
        start_line_number: record.thread.start_line_number,
        end_line_number: record.thread.end_line_number,
        start_offset: record.thread.start_offset,
        end_offset: record.thread.end_offset,
        created_by: record.thread.created_by,
        created_by_name: record.thread.created_by_name,
        created_at: record.thread.created_at,
        updated_at: record.thread.updated_at,
        resolved_at: record.thread.resolved_at,
        resolved_by: record.thread.resolved_by,
        replies: record.replies.into_iter().map(to_domain_reply).collect(),
    }
}

impl DocumentService {
    pub async fn list_comments(
        &self,
        actor: &Actor,
        doc_id: Uuid,
    ) -> Result<Vec<DomainCommentThread>, ServiceError> {
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|err| match err {
            ServiceError::Forbidden => ServiceError::NotFound,
            other => other,
        })?;
        let doc = self
            .document_repo
            .get_by_id(doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        let records = self
            .comment_repo
            .list_threads(doc.workspace_id(), doc_id)
            .await
            .map_err(ServiceError::from)?;
        Ok(records.into_iter().map(to_domain_thread).collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_comment_thread(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        thread_id: Uuid,
        marker: String,
        quote: String,
        body: String,
        start_line_number: Option<i32>,
        end_line_number: Option<i32>,
        start_offset: Option<i32>,
        end_offset: Option<i32>,
        author_name: Option<String>,
    ) -> Result<DomainCommentThread, ServiceError> {
        validate_marker(&marker)?;
        validate_body(&body)?;
        access::require_edit(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|err| match err {
            ServiceError::Forbidden => ServiceError::Unauthorized,
            other => other,
        })?;
        let doc = self
            .document_repo
            .get_by_id(doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        let created_by = actor_user_id(actor);
        let record = self
            .comment_repo
            .create_thread(NewCommentThread {
                id: thread_id,
                document_id: doc_id,
                workspace_id: doc.workspace_id(),
                marker,
                quote,
                start_line_number,
                end_line_number,
                start_offset,
                end_offset,
                created_by,
                created_by_name: author_name,
                reply_id: Uuid::new_v4(),
                body,
            })
            .await
            .map_err(ServiceError::from)?;
        Ok(to_domain_thread(record))
    }

    pub async fn add_comment_reply(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        thread_id: Uuid,
        body: String,
        author_name: Option<String>,
    ) -> Result<DomainCommentReply, ServiceError> {
        validate_body(&body)?;
        access::require_edit(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|err| match err {
            ServiceError::Forbidden => ServiceError::Unauthorized,
            other => other,
        })?;
        let record = self
            .comment_repo
            .add_reply(NewCommentReply {
                id: Uuid::new_v4(),
                thread_id,
                document_id: doc_id,
                body,
                created_by: actor_user_id(actor),
                created_by_name: author_name,
            })
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        Ok(to_domain_reply(record))
    }

    pub async fn set_comment_resolved(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        thread_id: Uuid,
        resolved: bool,
    ) -> Result<DomainCommentThread, ServiceError> {
        access::require_edit(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|err| match err {
            ServiceError::Forbidden => ServiceError::Unauthorized,
            other => other,
        })?;
        let doc = self
            .document_repo
            .get_by_id(doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        let record = self
            .comment_repo
            .set_resolved(
                doc.workspace_id(),
                doc_id,
                thread_id,
                actor_user_id(actor),
                resolved,
            )
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        Ok(to_domain_thread(record))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_bad_request(result: Result<(), ServiceError>, expected: &'static str) {
        match result {
            Err(ServiceError::BadRequest(actual)) => assert_eq!(actual, expected),
            other => panic!("expected bad request {expected}, got {other:?}"),
        }
    }

    #[test]
    fn validate_marker_accepts_markdown_comment_marker_ids() {
        assert!(validate_marker("<!--comment:abc_DEF-123-->").is_ok());
        assert!(validate_marker("<!--comment:550e8400-e29b-41d4-a716-446655440000-->").is_ok());
    }

    #[test]
    fn validate_marker_rejects_malformed_markers() {
        for marker in [
            "",
            "<!--comment:-->",
            "<!-- comment:abc -->",
            "<!--comment:abc def-->",
            "<!--comment:abc/def-->",
            "comment:abc",
        ] {
            assert_bad_request(validate_marker(marker), "invalid_comment_marker");
        }
    }

    #[test]
    fn validate_body_requires_visible_content() {
        assert!(validate_body("suggest changing this sentence").is_ok());
        assert_bad_request(validate_body("   \n\t  "), "comment_body_required");
    }
}
