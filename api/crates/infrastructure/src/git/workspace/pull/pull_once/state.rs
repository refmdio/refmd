impl GitWorkspaceService {
fn pull_collect_state_from_commit(
    repo: &Repository,
    oid: git2::Oid,
) -> anyhow::Result<HashMap<String, FileSnapshot>> {
    let commit = repo.find_commit(oid)?;
    let tree = commit.tree()?;
    let mut out: HashMap<String, FileSnapshot> = HashMap::new();

    fn walk(
        repo: &Repository,
        tree: &git2::Tree,
        prefix: &str,
        out: &mut HashMap<String, FileSnapshot>,
    ) -> anyhow::Result<()> {
        for entry in tree.iter() {
            let name = entry.name().unwrap_or_default();
            let path = if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{prefix}{name}")
            };
            match entry.kind() {
                Some(git2::ObjectType::Tree) => {
                    if let Some(sub) = entry.to_object(repo)?.as_tree() {
                        walk(repo, sub, &(path.clone() + "/"), out)?;
                    }
                }
                Some(git2::ObjectType::Blob) => {
                    let blob = repo.find_blob(entry.id())?;
                    let bytes = blob.content().to_vec();
                    let hash = sha256_hex(&bytes);
                    let is_text = std::str::from_utf8(&bytes).is_ok();
                    out.insert(
                        path,
                        FileSnapshot {
                            hash,
                            data: FileSnapshotData::Inline(bytes),
                            is_text,
                        },
                    );
                }
                _ => {}
            }
        }
        Ok(())
    }

    walk(repo, &tree, "", &mut out)?;
    Ok(out)
}

fn pull_remote_changed_paths(
    base_index: &HashMap<String, String>,
    remote_state: &HashMap<String, FileSnapshot>,
) -> Vec<String> {
    let mut remote_changed_paths: HashSet<String> = HashSet::new();
    for (path, snap) in remote_state.iter() {
        if base_index.get(path) != Some(&snap.hash) {
            remote_changed_paths.insert(path.clone());
        }
    }
    for path in base_index.keys() {
        if !remote_state.contains_key(path) {
            remote_changed_paths.insert(path.clone());
        }
    }
    remote_changed_paths.into_iter().collect()
}

async fn pull_build_conflicts_for_paths(
    &self,
    workspace_id: Uuid,
    paths: &[String],
    current_state: &HashMap<String, FileSnapshot>,
    remote_state: &HashMap<String, FileSnapshot>,
    local_meta: Option<&CommitMeta>,
) -> anyhow::Result<Vec<GitPullConflictItemDto>> {
    let mut remote_conflicts: Vec<GitPullConflictItemDto> = Vec::new();
    for path in paths.iter() {
        let item = self
            .build_conflict_item(workspace_id, path, current_state, remote_state, local_meta)
            .await?;
        remote_conflicts.push(item);
    }
    Ok(remote_conflicts)
}
}
