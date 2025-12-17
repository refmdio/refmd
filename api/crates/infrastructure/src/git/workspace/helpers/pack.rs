use super::super::*;

pub(in super::super) fn apply_pack_to_repo(repo: &Repository, pack: &[u8]) -> anyhow::Result<()> {
    let objects_dir = repo.path().join("objects").join("pack");
    fs::create_dir_all(&objects_dir)?;
    let odb = repo.odb()?;
    let mut indexer = Indexer::new(Some(&odb), objects_dir.as_path(), 0o644, true)?;
    indexer.write_all(pack)?;
    indexer.commit()?;
    Ok(())
}

pub(in super::super) fn read_first_pack(repo_path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
    let pack_dir = repo_path.join("objects").join("pack");
    if !pack_dir.exists() {
        return Ok(None);
    }
    let mut entries: Vec<_> = std::fs::read_dir(&pack_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "pack")
                .unwrap_or(false)
        })
        .collect();
    entries.sort_by_key(|e| e.file_name());
    if let Some(entry) = entries.first() {
        let bytes = std::fs::read(entry.path())?;
        return Ok(Some(bytes));
    }
    Ok(None)
}

pub(in super::super) fn apply_pack_files(
    repo: &Repository,
    pack_paths: &[PathBuf],
) -> anyhow::Result<()> {
    for path in pack_paths {
        let bytes = fs::read(path)?;
        apply_pack_to_repo(repo, &bytes)?;
    }
    Ok(())
}
