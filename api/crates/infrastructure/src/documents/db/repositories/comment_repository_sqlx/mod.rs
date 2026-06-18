use std::collections::BTreeMap;

use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::core::db::PgPool;
use application::core::ports::errors::PortResult;
use application::documents::ports::comment_repository::{
    CommentReplyRecord, CommentRepository, CommentThreadRecord, CommentThreadWithReplies,
    NewCommentReply, NewCommentThread,
};

pub struct SqlxCommentRepository {
    pub pool: PgPool,
}

impl SqlxCommentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn row_to_thread(row: sqlx::postgres::PgRow) -> CommentThreadRecord {
    CommentThreadRecord {
        id: row.get("id"),
        document_id: row.get("document_id"),
        marker: row.get("marker"),
        quote: row.get("quote"),
        start_line_number: row.try_get("start_line_number").ok(),
        end_line_number: row.try_get("end_line_number").ok(),
        start_offset: row.try_get("start_offset").ok(),
        end_offset: row.try_get("end_offset").ok(),
        created_by: row.try_get("created_by").ok(),
        created_by_name: row.try_get("created_by_name").ok(),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        resolved_at: row.try_get("resolved_at").ok(),
        resolved_by: row.try_get("resolved_by").ok(),
    }
}

fn row_to_reply(row: sqlx::postgres::PgRow) -> CommentReplyRecord {
    CommentReplyRecord {
        id: row.get("id"),
        thread_id: row.get("thread_id"),
        document_id: row.get("document_id"),
        body: row.get("body"),
        created_by: row.try_get("created_by").ok(),
        created_by_name: row.try_get("created_by_name").ok(),
        created_at: row.get("created_at"),
    }
}

async fn replies_for(
    pool: &PgPool,
    document_id: Uuid,
    thread_ids: &[Uuid],
) -> anyhow::Result<BTreeMap<Uuid, Vec<CommentReplyRecord>>> {
    if thread_ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let rows = sqlx::query(
        r#"SELECT id, thread_id, document_id, body, created_by, created_by_name, created_at
           FROM document_comment_replies
           WHERE document_id = $1 AND thread_id = ANY($2)
           ORDER BY created_at ASC"#,
    )
    .bind(document_id)
    .bind(thread_ids)
    .fetch_all(pool)
    .await?;

    let mut grouped: BTreeMap<Uuid, Vec<CommentReplyRecord>> = BTreeMap::new();
    for row in rows {
        let reply = row_to_reply(row);
        grouped.entry(reply.thread_id).or_default().push(reply);
    }
    Ok(grouped)
}

#[async_trait]
impl CommentRepository for SqlxCommentRepository {
    async fn list_threads(
        &self,
        workspace_id: Uuid,
        document_id: Uuid,
    ) -> PortResult<Vec<CommentThreadWithReplies>> {
        let out: anyhow::Result<Vec<CommentThreadWithReplies>> = async {
            let rows = sqlx::query(
                r#"SELECT id, document_id, marker, quote, start_line_number, end_line_number,
                          start_offset, end_offset, created_by, created_by_name, created_at,
                          updated_at, resolved_at, resolved_by
                   FROM document_comment_threads
                   WHERE workspace_id = $1 AND document_id = $2
                   ORDER BY resolved_at NULLS FIRST, created_at ASC"#,
            )
            .bind(workspace_id)
            .bind(document_id)
            .fetch_all(&self.pool)
            .await?;
            let threads = rows.into_iter().map(row_to_thread).collect::<Vec<_>>();
            let ids = threads.iter().map(|thread| thread.id).collect::<Vec<_>>();
            let mut replies = replies_for(&self.pool, document_id, &ids).await?;
            Ok(threads
                .into_iter()
                .map(|thread| CommentThreadWithReplies {
                    replies: replies.remove(&thread.id).unwrap_or_default(),
                    thread,
                })
                .collect())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn create_thread(&self, input: NewCommentThread) -> PortResult<CommentThreadWithReplies> {
        let out: anyhow::Result<CommentThreadWithReplies> = async {
            let mut tx = self.pool.begin().await?;
            let thread_row = sqlx::query(
                r#"INSERT INTO document_comment_threads (
                    id, document_id, workspace_id, marker, quote, start_line_number, end_line_number,
                    start_offset, end_offset, created_by, created_by_name, created_at, updated_at
                   ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now(), now())
                   RETURNING id, document_id, marker, quote, start_line_number, end_line_number,
                             start_offset, end_offset, created_by, created_by_name, created_at,
                             updated_at, resolved_at, resolved_by"#,
            )
            .bind(input.id)
            .bind(input.document_id)
            .bind(input.workspace_id)
            .bind(input.marker)
            .bind(input.quote)
            .bind(input.start_line_number)
            .bind(input.end_line_number)
            .bind(input.start_offset)
            .bind(input.end_offset)
            .bind(input.created_by)
            .bind(input.created_by_name.clone())
            .fetch_one(&mut *tx)
            .await?;

            let reply_row = sqlx::query(
                r#"INSERT INTO document_comment_replies (
                    id, thread_id, document_id, body, created_by, created_by_name, created_at
                   ) VALUES ($1, $2, $3, $4, $5, $6, now())
                   RETURNING id, thread_id, document_id, body, created_by, created_by_name, created_at"#,
            )
            .bind(input.reply_id)
            .bind(input.id)
            .bind(input.document_id)
            .bind(input.body)
            .bind(input.created_by)
            .bind(input.created_by_name)
            .fetch_one(&mut *tx)
            .await?;

            tx.commit().await?;
            Ok(CommentThreadWithReplies {
                thread: row_to_thread(thread_row),
                replies: vec![row_to_reply(reply_row)],
            })
        }
        .await;
        out.map_err(Into::into)
    }

    async fn add_reply(&self, input: NewCommentReply) -> PortResult<Option<CommentReplyRecord>> {
        let out: anyhow::Result<Option<CommentReplyRecord>> = async {
            let row = sqlx::query(
                r#"INSERT INTO document_comment_replies (
                    id, thread_id, document_id, body, created_by, created_by_name, created_at
                   )
                   SELECT $1, t.id, t.document_id, $4, $5, $6, now()
                   FROM document_comment_threads t
                   WHERE t.id = $2 AND t.document_id = $3
                   RETURNING id, thread_id, document_id, body, created_by, created_by_name, created_at"#,
            )
            .bind(input.id)
            .bind(input.thread_id)
            .bind(input.document_id)
            .bind(input.body)
            .bind(input.created_by)
            .bind(input.created_by_name)
            .fetch_optional(&self.pool)
            .await?;

            let Some(row) = row else {
                return Ok(None);
            };

            sqlx::query("UPDATE document_comment_threads SET updated_at = now() WHERE id = $1")
                .bind(input.thread_id)
                .execute(&self.pool)
                .await?;

            Ok(Some(row_to_reply(row)))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn set_resolved(
        &self,
        workspace_id: Uuid,
        document_id: Uuid,
        thread_id: Uuid,
        resolved_by: Option<Uuid>,
        resolved: bool,
    ) -> PortResult<Option<CommentThreadWithReplies>> {
        let out: anyhow::Result<Option<CommentThreadWithReplies>> = async {
            let row = sqlx::query(
                r#"UPDATE document_comment_threads
                   SET resolved_at = CASE WHEN $4 THEN now() ELSE NULL END,
                       resolved_by = CASE WHEN $4 THEN $5 ELSE NULL END,
                       updated_at = now()
                   WHERE workspace_id = $1 AND document_id = $2 AND id = $3
                   RETURNING id, document_id, marker, quote, start_line_number, end_line_number,
                             start_offset, end_offset, created_by, created_by_name, created_at,
                             updated_at, resolved_at, resolved_by"#,
            )
            .bind(workspace_id)
            .bind(document_id)
            .bind(thread_id)
            .bind(resolved)
            .bind(resolved_by)
            .fetch_optional(&self.pool)
            .await?;

            let Some(row) = row else {
                return Ok(None);
            };
            let thread = row_to_thread(row);
            let mut replies = replies_for(&self.pool, document_id, &[thread.id]).await?;
            Ok(Some(CommentThreadWithReplies {
                replies: replies.remove(&thread.id).unwrap_or_default(),
                thread,
            }))
        }
        .await;
        out.map_err(Into::into)
    }
}
