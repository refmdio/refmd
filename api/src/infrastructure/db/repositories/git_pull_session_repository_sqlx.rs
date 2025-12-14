use async_trait::async_trait;
use sqlx::types::Json;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::application::dto::git::{
    GitPullConflictItemDto, GitPullResolutionDto, GitPullSessionDto,
};
use crate::application::ports::git_pull_session_repository::GitPullSessionRepository;

pub struct GitPullSessionRepositorySqlx {
    pool: PgPool,
}

impl GitPullSessionRepositorySqlx {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl GitPullSessionRepository for GitPullSessionRepositorySqlx {
    async fn upsert(&self, session: GitPullSessionDto) -> anyhow::Result<()> {
        let GitPullSessionDto {
            id,
            workspace_id,
            status,
            conflicts,
            resolutions,
            message,
            base_commit,
            remote_commit,
        } = session;
        sqlx::query(
            r#"INSERT INTO git_pull_sessions (id, workspace_id, status, conflicts, resolutions, created_at, updated_at, message, base_commit, remote_commit)
                VALUES ($1, $2, $3, $4, $5, now(), now(), $6, $7, $8)
                ON CONFLICT (id) DO UPDATE SET
                  status = EXCLUDED.status,
                  conflicts = EXCLUDED.conflicts,
                  resolutions = EXCLUDED.resolutions,
                  message = EXCLUDED.message,
                  base_commit = EXCLUDED.base_commit,
                  remote_commit = EXCLUDED.remote_commit,
                  updated_at = now()"#,
        )
        .bind(id)
        .bind(workspace_id)
        .bind(status)
        .bind(Json(conflicts))
        .bind(Json(resolutions))
        .bind(message.clone())
        .bind(base_commit.clone())
        .bind(remote_commit.clone())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get(&self, workspace_id: Uuid, id: Uuid) -> anyhow::Result<Option<GitPullSessionDto>> {
        let row = sqlx::query(
            r#"SELECT id, workspace_id, status, conflicts, resolutions, message, base_commit, remote_commit FROM git_pull_sessions
                WHERE id = $1 AND workspace_id = $2"#,
        )
        .bind(id)
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };
        let conflicts: Vec<GitPullConflictItemDto> = row
            .get::<Json<Vec<GitPullConflictItemDto>>, _>("conflicts")
            .0;
        let resolutions: Vec<GitPullResolutionDto> = row
            .get::<Json<Vec<GitPullResolutionDto>>, _>("resolutions")
            .0;
        Ok(Some(GitPullSessionDto {
            id,
            workspace_id,
            status: row.get::<String, _>("status"),
            conflicts,
            resolutions,
            message: row.try_get::<Option<String>, _>("message").unwrap_or(None),
            base_commit: row.get::<Option<Vec<u8>>, _>("base_commit"),
            remote_commit: row.get::<Option<Vec<u8>>, _>("remote_commit"),
        }))
    }
}
