impl GitWorkspaceService {
fn pull_build_commit_meta_and_pack(
    repo: &Repository,
    workspace_id: Uuid,
    oid: git2::Oid,
    file_hash_index: HashMap<String, String>,
) -> anyhow::Result<(CommitMeta, Vec<u8>)> {
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
        Some(commit.parent_id(0)?.as_bytes().to_vec())
    } else {
        None
    };

    let mut pack_builder = repo.packbuilder()?;
    pack_builder.insert_commit(oid)?;
    if let Some(parent_id) = parent_commit_id.as_ref() {
        if let Ok(parent_oid) = git2::Oid::from_bytes(parent_id) {
            let _ = pack_builder.insert_commit(parent_oid);
        }
    }
    let mut pack_buf = git2::Buf::new();
    pack_builder.write_buf(&mut pack_buf)?;
    let pack_bytes = pack_buf.to_vec();

    let commit_hex = encode_commit_id(oid.as_bytes());
    let meta = CommitMeta {
        commit_id: oid.as_bytes().to_vec(),
        parent_commit_id,
        message,
        author_name,
        author_email,
        committed_at,
        pack_key: format!("git/packs/{}/{}.pack", workspace_id, commit_hex),
        file_hash_index,
    };

    Ok((meta, pack_bytes))
}
}
