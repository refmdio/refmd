impl GitWorkspaceService {
async fn pull_build_fallback_diff_conflicts(
    &self,
    workspace_id: Uuid,
    local_oid: Option<git2::Oid>,
    remote_oid: git2::Oid,
    current_state: &HashMap<String, FileSnapshot>,
    remote_state: &HashMap<String, FileSnapshot>,
    local_meta: Option<&CommitMeta>,
) -> anyhow::Result<Vec<GitPullConflictItemDto>> {
    let local_oid_val = local_oid.unwrap_or(remote_oid);
    if remote_oid == local_oid_val {
        return Ok(Vec::new());
    }

    let mut all_paths: HashSet<String> = HashSet::new();
    for p in remote_state.keys() {
        all_paths.insert(p.clone());
    }
    for p in current_state.keys() {
        all_paths.insert(p.clone());
    }

    let mut remote_conflicts: Vec<GitPullConflictItemDto> = Vec::new();
    for path in all_paths {
        let remote_hash = remote_state.get(&path).map(|s| &s.hash);
        let local_hash = current_state.get(&path).map(|s| &s.hash);
        if remote_hash == local_hash {
            continue;
        }

        let item = self
            .build_conflict_item(workspace_id, &path, current_state, remote_state, local_meta)
            .await?;
        remote_conflicts.push(item);
    }

    Ok(remote_conflicts)
}
}
