impl GitWorkspaceService {
    async fn sync_persist_commit(
        &self,
        workspace_id: Uuid,
        use_full_scan: bool,
        meta: &CommitMeta,
        pack_bytes: &[u8],
        changed_text_snapshots: &HashMap<String, FileSnapshot>,
        latest_meta_for_rollback: Option<&CommitMeta>,
    ) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        let repo_row =
            sqlx::query("SELECT initialized FROM git_repository_state WHERE workspace_id = $1")
                .bind(workspace_id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(repo_row) = repo_row else {
            tx.rollback().await.ok();
            anyhow::bail!("repository not initialized")
        };
        let initialized: bool = repo_row.get("initialized");
        if !initialized {
            tx.rollback().await.ok();
            anyhow::bail!("repository not initialized")
        }

        sqlx::query(
            r#"INSERT INTO git_commits (
                    commit_id,
                    parent_commit_id,
                    workspace_id,
                    message,
                    author_name,
                    author_email,
                    committed_at,
                    pack_key,
                    file_hash_index
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        )
        .bind(meta.commit_id.clone())
        .bind(meta.parent_commit_id.clone())
        .bind(workspace_id)
        .bind(meta.message.clone())
        .bind(meta.author_name.clone())
        .bind(meta.author_email.clone())
        .bind(meta.committed_at)
        .bind(meta.pack_key.clone())
        .bind(Json(&meta.file_hash_index))
        .execute(&mut *tx)
        .await?;

        sqlx::query("UPDATE git_repository_state SET updated_at = now() WHERE workspace_id = $1")
            .bind(workspace_id)
            .execute(&mut *tx)
            .await?;

        let snapshot_keys = if use_full_scan {
            let current = self.collect_current_state(workspace_id).await?;
            match self
                .store_commit_snapshots(workspace_id, &meta.commit_id, &current)
                .await
            {
                Ok(keys) => keys,
                Err(err) => {
                    tx.rollback().await.ok();
                    return Err(err);
                }
            }
        } else {
            match self
                .store_commit_snapshots(workspace_id, &meta.commit_id, changed_text_snapshots)
                .await
            {
                Ok(keys) => keys,
                Err(err) => {
                    tx.rollback().await.ok();
                    return Err(err);
                }
            }
        };

        if let Err(err) = self
            .git_storage
            .store_pack(workspace_id, pack_bytes, meta)
            .await
        {
            for key in snapshot_keys.iter().rev() {
                let _ = self.git_storage.delete_blob(key).await;
            }
            tx.rollback().await.ok();
            return Err(err.into());
        }

        if let Err(err) = self
            .git_storage
            .set_latest_commit(workspace_id, Some(meta))
            .await
        {
            let _ = self
                .git_storage
                .delete_pack(workspace_id, &meta.commit_id)
                .await;
            for key in snapshot_keys.iter().rev() {
                let _ = self.git_storage.delete_blob(key).await;
            }
            tx.rollback().await.ok();
            return Err(err.into());
        }

        if let Err(err) = tx.commit().await {
            let _ = self
                .git_storage
                .delete_pack(workspace_id, &meta.commit_id)
                .await;
            for key in snapshot_keys.iter().rev() {
                let _ = self.git_storage.delete_blob(key).await;
            }
            let _ = self
                .git_storage
                .set_latest_commit(workspace_id, latest_meta_for_rollback)
                .await;
            return Err(err.into());
        }

        self.clear_dirty(workspace_id).await.map_err(|err| {
            error!(workspace_id = %workspace_id, error = %err, "git_import_clear_dirty_failed");
            err
        })?;
        Ok(())
    }
}
