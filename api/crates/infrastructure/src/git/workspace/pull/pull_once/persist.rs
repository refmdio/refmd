impl GitWorkspaceService {
async fn pull_fast_forward_to_remote(
    &self,
    workspace_id: Uuid,
    actor_id: Uuid,
    base_commit: Option<Vec<u8>>,
    previous_index: &HashMap<String, String>,
    remote_state: &HashMap<String, FileSnapshot>,
    remote_meta: &CommitMeta,
    remote_pack_bytes: Option<&[u8]>,
) -> anyhow::Result<GitPullResultDto> {
    if let Some(pack_bytes) = remote_pack_bytes {
        self.git_storage
            .store_pack(workspace_id, pack_bytes, remote_meta)
            .await?;
    }
    self.upsert_commit_record(workspace_id, remote_meta).await?;

    let snapshot_keys = self
        .store_commit_snapshots(workspace_id, &remote_meta.commit_id, remote_state)
        .await?;

    if let Err(err) = self
        .git_storage
        .set_latest_commit(workspace_id, Some(remote_meta))
        .await
    {
        for key in snapshot_keys.iter().rev() {
            let _ = self.git_storage.delete_blob(key).await;
        }
        return Err(err);
    }

    let mut tx = self.pool.begin().await?;
    let repo_row = sqlx::query("SELECT initialized FROM git_repository_state WHERE workspace_id = $1")
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
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            ON CONFLICT (commit_id, workspace_id) DO NOTHING"#,
    )
    .bind(remote_meta.commit_id.clone())
    .bind(remote_meta.parent_commit_id.clone())
    .bind(workspace_id)
    .bind(remote_meta.message.clone())
    .bind(remote_meta.author_name.clone())
    .bind(remote_meta.author_email.clone())
    .bind(remote_meta.committed_at)
    .bind(remote_meta.pack_key.clone())
    .bind(Json(&remote_meta.file_hash_index))
    .execute(&mut *tx)
    .await?;

    sqlx::query("UPDATE git_repository_state SET updated_at = now() WHERE workspace_id = $1")
        .bind(workspace_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    let files_changed = self
        .apply_state_to_workspace(workspace_id, remote_state, previous_index)
        .await?;

    self.materialize_documents_from_state(workspace_id, actor_id, remote_state)
        .await?;
    self.apply_merged_to_documents(workspace_id, remote_state)
        .await?;
    self.clear_dirty(workspace_id).await.map_err(|err| {
        error!(
            workspace_id = %workspace_id,
            error = %err,
            "git_pull_clear_dirty_failed"
        );
        err
    })?;

    info!(
        workspace_id = %workspace_id,
        commit = %encode_commit_id(&remote_meta.commit_id),
        "git_pull_fast_forward_remote"
    );

    Ok(GitPullResultDto {
        success: true,
        message: "fast-forwarded to remote".to_string(),
        files_changed,
        commit_hash: Some(encode_commit_id(&remote_meta.commit_id)),
        conflicts: None,
        base_commit,
        remote_commit: Some(remote_meta.commit_id.clone()),
    })
}

async fn pull_persist_merged_commit(
    &self,
    workspace_id: Uuid,
    actor_id: Uuid,
    previous_index: &HashMap<String, String>,
    base_commit: Option<Vec<u8>>,
    remote_commit: Option<Vec<u8>>,
    remote_pack: Option<(CommitMeta, Vec<u8>)>,
    meta: CommitMeta,
    pack_bytes: Vec<u8>,
    merged_snapshots: HashMap<String, FileSnapshot>,
    commit_hex: String,
) -> anyhow::Result<GitPullResultDto> {
    if let Some((remote_meta, remote_pack_bytes)) = remote_pack {
        self.git_storage
            .store_pack(workspace_id, &remote_pack_bytes, &remote_meta)
            .await?;
        self.upsert_commit_record(workspace_id, &remote_meta).await?;
    }

    let snapshot_keys = self
        .store_commit_snapshots(workspace_id, &meta.commit_id, &merged_snapshots)
        .await?;

    if let Err(err) = self
        .git_storage
        .store_pack(workspace_id, &pack_bytes, &meta)
        .await
    {
        for key in snapshot_keys.iter().rev() {
            let _ = self.git_storage.delete_blob(key).await;
        }
        return Err(err);
    }

    if let Err(err) = self
        .git_storage
        .set_latest_commit(workspace_id, Some(&meta))
        .await
    {
        let _ = self.git_storage.delete_pack(workspace_id, &meta.commit_id).await;
        for key in snapshot_keys.iter().rev() {
            let _ = self.git_storage.delete_blob(key).await;
        }
        return Err(err);
    }

    let mut tx = self.pool.begin().await?;
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
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)"#,
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
    tx.commit().await?;

    let files_changed = self
        .apply_state_to_workspace(workspace_id, &merged_snapshots, previous_index)
        .await?;

    self.materialize_documents_from_state(workspace_id, actor_id, &merged_snapshots)
        .await?;
    self.apply_merged_to_documents(workspace_id, &merged_snapshots)
        .await?;

    self.clear_dirty(workspace_id).await.map_err(|err| {
        error!(
            workspace_id = %workspace_id,
            error = %err,
            "git_pull_merge_clear_dirty_failed"
        );
        err
    })?;

    Ok(GitPullResultDto {
        success: true,
        message: "remote changes merged".to_string(),
        files_changed,
        commit_hash: Some(commit_hex),
        conflicts: None,
        base_commit,
        remote_commit,
    })
}
}
