impl GitWorkspaceService {
fn pull_dirty_remote_overlap(dirty_rows: &[DirtyRow], remote_changed_paths: &[String]) -> bool {
    let dirty_paths: HashSet<String> = dirty_rows.iter().map(|r| r.path.clone()).collect();
    remote_changed_paths.iter().any(|p| dirty_paths.contains(p))
}

fn pull_conflicts_detected_response(
    base_commit: Option<Vec<u8>>,
    remote_commit: Option<Vec<u8>>,
    conflicts: Vec<GitPullConflictItemDto>,
) -> GitPullResultDto {
    GitPullResultDto {
        success: false,
        message: "conflicts detected".to_string(),
        files_changed: 0,
        commit_hash: None,
        conflicts: Some(conflicts),
        base_commit,
        remote_commit,
    }
}
}
