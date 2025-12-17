use super::super::*;

use super::tree::{DirEntry, DirNode, write_dir};

#[allow(dead_code)]
pub(in super::super) fn read_commit_files(
    repo: &Repository,
    commit_id: &[u8],
) -> anyhow::Result<HashMap<String, Vec<u8>>> {
    let oid = git2::Oid::from_bytes(commit_id)?;
    let commit = repo.find_commit(oid)?;
    let tree = commit.tree()?;
    let mut files = HashMap::new();
    tree.walk(TreeWalkMode::PreOrder, |root, entry| {
        if entry.kind() == Some(ObjectType::Blob) {
            if let Some(name) = entry.name() {
                if let Ok(blob) = repo.find_blob(entry.id()) {
                    let key = format!("{}{}", root, name);
                    files.insert(key, blob.content().to_vec());
                }
            }
        }
        TreeWalkResult::Ok
    })?;
    Ok(files)
}

pub(in super::super) enum FileSnapshotData {
    Inline(Vec<u8>),
    StoragePath(String),
}

pub(in super::super) struct FileSnapshot {
    pub(in super::super) hash: String,
    pub(in super::super) data: FileSnapshotData,
    pub(in super::super) is_text: bool,
}

pub(in super::super) struct FileDeltaSummary {
    pub(in super::super) added: Vec<String>,
    pub(in super::super) modified: Vec<String>,
    pub(in super::super) deleted: Vec<String>,
}

pub(in super::super) struct DirtyRow {
    pub(in super::super) path: String,
    pub(in super::super) is_text: bool,
    pub(in super::super) op: String,
    pub(in super::super) content_hash: Option<String>,
}

pub(in super::super) struct DirtyUpsert {
    pub(in super::super) is_text: bool,
    pub(in super::super) content_hash: Option<String>,
}

pub(in super::super) fn repo_relative_path(path: &str) -> anyhow::Result<String> {
    let trimmed = path.trim_start_matches('/');
    let mut parts = trimmed.splitn(2, '/');
    let leading = parts.next().unwrap_or("");
    if let Some(rest) = parts.next() {
        Ok(rest.replace('\\', "/"))
    } else if !leading.is_empty() {
        Ok(leading.replace('\\', "/"))
    } else {
        Err(anyhow!("invalid storage path for repository: {path}"))
    }
}

pub(in super::super) fn normalize_repo_path(path: String) -> String {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        trimmed
            .replace('\\', "/")
            .trim_start_matches("./")
            .trim_start_matches('/')
            .to_string()
    }
}

pub(in super::super) fn blob_key(workspace_id: Uuid, commit_id: &[u8], path: &str) -> BlobKey {
    let encoded_path = urlencoding::encode(path);
    let commit_hex = encode_commit_id(commit_id);
    BlobKey {
        path: format!("{}/{}/{}", workspace_id, commit_hex, encoded_path),
    }
}

pub(in super::super) enum FileSource {
    Bytes(Vec<u8>),
    Oid(git2::Oid),
}

pub(in super::super) fn insert_source_into_dir(
    dir: &mut DirNode,
    parts: &[&str],
    source: &FileSource,
) -> anyhow::Result<()> {
    use std::collections::btree_map::Entry;
    if parts.is_empty() {
        return Ok(());
    }
    if parts.len() == 1 {
        match source {
            FileSource::Bytes(data) => {
                dir.entries
                    .insert(parts[0].to_string(), DirEntry::File(data.clone()));
            }
            FileSource::Oid(oid) => {
                dir.entries
                    .insert(parts[0].to_string(), DirEntry::Oid(*oid));
            }
        }
        Ok(())
    } else {
        match dir.entries.entry(parts[0].to_string()) {
            Entry::Occupied(mut occ) => match occ.get_mut() {
                DirEntry::Dir(child) => insert_source_into_dir(child, &parts[1..], source),
                DirEntry::File(_) | DirEntry::Oid(_) => {
                    let mut new_dir = DirNode::default();
                    insert_source_into_dir(&mut new_dir, &parts[1..], source)?;
                    *occ.get_mut() = DirEntry::Dir(Box::new(new_dir));
                    Ok(())
                }
            },
            Entry::Vacant(vac) => {
                let mut new_dir = DirNode::default();
                insert_source_into_dir(&mut new_dir, &parts[1..], source)?;
                vac.insert(DirEntry::Dir(Box::new(new_dir)));
                Ok(())
            }
        }
    }
}

pub(in super::super) fn read_commit_blob_oids(
    repo: &Repository,
    commit_id: &[u8],
) -> anyhow::Result<HashMap<String, git2::Oid>> {
    let oid = git2::Oid::from_bytes(commit_id)?;
    let commit = repo.find_commit(oid)?;
    let tree = commit.tree()?;
    let mut blobs = HashMap::new();
    tree.walk(TreeWalkMode::PreOrder, |root, entry| {
        if entry.kind() == Some(ObjectType::Blob) {
            if let Some(name) = entry.name() {
                let key = format!("{}{}", root, name);
                blobs.insert(key, entry.id());
            }
        }
        TreeWalkResult::Ok
    })?;
    Ok(blobs)
}

pub(in super::super) fn build_tree_from_sources(
    repo: &Repository,
    entries: &BTreeMap<String, FileSource>,
) -> anyhow::Result<git2::Oid> {
    // We'll reconstruct a DirNode and then write it, but we need to preserve existing blob OIDs for FileSource::Oid.
    let mut root = DirNode::default();
    for (path, src) in entries.iter() {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            continue;
        }
        insert_source_into_dir(&mut root, &parts, src)?;
    }
    write_dir(repo, &root)
}
