use super::super::*;

pub(in super::super) fn build_tree_from_entries(
    repo: &Repository,
    entries: &BTreeMap<String, Vec<u8>>,
) -> anyhow::Result<git2::Oid> {
    let mut root = DirNode::default();
    for (path, data) in entries.iter() {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            continue;
        }
        insert_into_dir(&mut root, &parts, data.clone());
    }
    write_dir(repo, &root)
}

pub(in super::super) fn signature_from_parts(
    name: &str,
    email: &str,
    at: DateTime<Utc>,
) -> anyhow::Result<Signature<'static>> {
    let git_time = Time::new(at.timestamp(), 0);
    Signature::new(name, email, &git_time).map_err(anyhow::Error::from)
}

pub(in super::super) fn git_time_to_datetime(time: Time) -> anyhow::Result<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(time.seconds(), 0)
        .ok_or_else(|| anyhow!("invalid git timestamp"))
}

#[derive(Default)]
pub(in super::super) struct DirNode {
    pub(in super::super) entries: BTreeMap<String, DirEntry>,
}

pub(in super::super) enum DirEntry {
    File(Vec<u8>),
    Oid(git2::Oid),
    Dir(Box<DirNode>),
}

pub(in super::super) fn insert_into_dir(dir: &mut DirNode, parts: &[&str], data: Vec<u8>) {
    use std::collections::btree_map::Entry;

    if parts.is_empty() {
        return;
    }

    if parts.len() == 1 {
        dir.entries
            .insert(parts[0].to_string(), DirEntry::File(data));
        return;
    }

    match dir.entries.entry(parts[0].to_string()) {
        Entry::Occupied(mut occ) => {
            let next = occ.get_mut();
            match next {
                DirEntry::Dir(child) => insert_into_dir(child, &parts[1..], data),
                DirEntry::File(_) | DirEntry::Oid(_) => {
                    let mut new_dir = DirNode::default();
                    insert_into_dir(&mut new_dir, &parts[1..], data);
                    *next = DirEntry::Dir(Box::new(new_dir));
                }
            }
        }
        Entry::Vacant(vac) => {
            if parts.len() == 1 {
                vac.insert(DirEntry::File(data));
            } else {
                let mut new_dir = DirNode::default();
                insert_into_dir(&mut new_dir, &parts[1..], data);
                vac.insert(DirEntry::Dir(Box::new(new_dir)));
            }
        }
    }
}

pub(in super::super) fn write_dir(repo: &Repository, dir: &DirNode) -> anyhow::Result<git2::Oid> {
    let mut builder = repo.treebuilder(None)?;
    for (name, entry) in dir.entries.iter() {
        match entry {
            DirEntry::File(content) => {
                let oid = repo.blob(content)?;
                builder.insert(name, oid, FileMode::Blob.into())?;
            }
            DirEntry::Oid(oid) => {
                builder.insert(name, *oid, FileMode::Blob.into())?;
            }
            DirEntry::Dir(child) => {
                let oid = write_dir(repo, child)?;
                builder.insert(name, oid, FileMode::Tree.into())?;
            }
        }
    }
    Ok(builder.write()?)
}
