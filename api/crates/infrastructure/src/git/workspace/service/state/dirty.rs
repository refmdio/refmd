impl GitWorkspaceService {
    async fn fetch_dirty(&self, workspace_id: Uuid) -> anyhow::Result<Vec<DirtyRow>> {
        let rows = sqlx::query(
            r#"SELECT path, is_text, op, content_hash
               FROM git_dirty_files
               WHERE workspace_id = $1
               ORDER BY created_at ASC"#,
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let path: String = r.get("path");
            let is_text: bool = r.get("is_text");
            let op: String = r.get("op");
            let content_hash: Option<String> = r.try_get("content_hash").ok();
            out.push(DirtyRow {
                path,
                is_text,
                op,
                content_hash,
            });
        }
        Ok(out)
    }

    async fn clear_dirty(&self, workspace_id: Uuid) -> anyhow::Result<u64> {
        let res = sqlx::query("DELETE FROM git_dirty_files WHERE workspace_id = $1")
            .bind(workspace_id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }
}
