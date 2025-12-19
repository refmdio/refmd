impl GitWorkspaceService {
    async fn repair_missing_commit_metadata(
        &self,
        workspace_id: Uuid,
        start_hex: &str,
    ) -> anyhow::Result<()> {
        let mut current_hex = start_hex.to_string();
        let mut visited = HashSet::new();
        loop {
            if !visited.insert(current_hex.clone()) {
                break;
            }
            let meta =
                if let Some(meta) = self.commit_meta_by_hex(workspace_id, &current_hex).await? {
                    meta
                } else if let Some(meta) = self
                    .reconstruct_commit_meta_from_pack(workspace_id, &current_hex)
                    .await?
                {
                    meta
                } else {
                    anyhow::bail!(
                        "commit {} not found in database or pack storage",
                        current_hex
                    );
                };
            self.git_storage
                .restore_commit_meta(workspace_id, &meta)
                .await?;
            self.upsert_commit_record(workspace_id, &meta).await?;
            if let Some(parent) = meta.parent_commit_id.as_ref() {
                current_hex = encode_commit_id(parent);
            } else {
                break;
            }
        }
        Ok(())
    }

    async fn upsert_commit_record(
        &self,
        workspace_id: Uuid,
        meta: &CommitMeta,
    ) -> anyhow::Result<()> {
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
                ON CONFLICT (workspace_id, commit_id) DO UPDATE SET
                    parent_commit_id = EXCLUDED.parent_commit_id,
                    message = EXCLUDED.message,
                    author_name = EXCLUDED.author_name,
                    author_email = EXCLUDED.author_email,
                    committed_at = EXCLUDED.committed_at,
                    pack_key = EXCLUDED.pack_key,
                    file_hash_index = EXCLUDED.file_hash_index"#,
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
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn reconstruct_commit_meta_from_pack(
        &self,
        workspace_id: Uuid,
        commit_hex: &str,
    ) -> anyhow::Result<Option<CommitMeta>> {
        let commit_id = decode_commit_id(commit_hex)?;
        let Some(pack_bytes) = self
            .git_storage
            .fetch_pack_for_commit(workspace_id, &commit_id)
            .await?
        else {
            return Ok(None);
        };
        let temp_dir = tempfile::tempdir()?;
        let repo = Repository::init_bare(temp_dir.path())?;
        apply_pack_to_repo(&repo, &pack_bytes)?;
        let oid = git2::Oid::from_bytes(&commit_id)?;
        let commit = repo.find_commit(oid)?;
        let committed_at = git_time_to_datetime(commit.time())?;
        let message = commit
            .message()
            .map(|m| m.trim_end_matches('\n').to_string())
            .filter(|m| !m.trim().is_empty());
        let author = commit.author();
        let author_name = author.name().map(|s| s.to_string());
        let author_email = author.email().map(|s| s.to_string());
        let parent_commit_id = if commit.parent_count() > 0 {
            let parent = commit.parent_id(0)?;
            Some(parent.as_bytes().to_vec())
        } else {
            None
        };
        let files = read_commit_files(&repo, commit_id.as_slice())?;
        let mut file_hash_index: HashMap<String, String> = HashMap::new();
        for (path, bytes) in files.into_iter() {
            file_hash_index.insert(path, sha256_hex(&bytes));
        }
        let meta = CommitMeta {
            commit_id,
            parent_commit_id,
            message,
            author_name,
            author_email,
            committed_at,
            pack_key: format!("git/packs/{}/{}.pack", workspace_id, commit_hex),
            file_hash_index,
        };
        Ok(Some(meta))
    }
}
