use super::super::*;

pub(in super::super) fn collect_conflicts(
    repo: &Repository,
    index: &git2::Index,
) -> anyhow::Result<Vec<GitPullConflictItemDto>> {
    let mut out = Vec::new();
    let mut conflicts = index.conflicts()?;
    while let Some(conflict) = conflicts.next() {
        let conflict = conflict?;
        let path = conflict
            .our
            .as_ref()
            .or(conflict.their.as_ref())
            .or(conflict.ancestor.as_ref())
            .and_then(|e| std::str::from_utf8(&e.path).ok())
            .unwrap_or("")
            .to_string();

        let to_bytes = |entry: Option<&git2::IndexEntry>| -> anyhow::Result<Option<Vec<u8>>> {
            if let Some(e) = entry {
                let blob = repo.find_blob(e.id)?;
                Ok(Some(blob.content().to_vec()))
            } else {
                Ok(None)
            }
        };

        let ours_bytes = to_bytes(conflict.our.as_ref())?;
        let theirs_bytes = to_bytes(conflict.their.as_ref())?;
        let base_bytes = to_bytes(conflict.ancestor.as_ref())?;

        let (mut ours, ours_bin) = as_text_or_binary(path.as_str(), ours_bytes.as_ref());
        let (mut theirs, theirs_bin) = as_text_or_binary(path.as_str(), theirs_bytes.as_ref());
        let (mut base, base_bin) = as_text_or_binary(path.as_str(), base_bytes.as_ref());
        let is_binary = ours_bin || theirs_bin || base_bin;
        if !is_binary {
            ours = super::strip_front_matter_body(path.as_str(), ours);
            theirs = super::strip_front_matter_body(path.as_str(), theirs);
            base = super::strip_front_matter_body(path.as_str(), base);
        }

        out.push(GitPullConflictItemDto {
            path,
            is_binary,
            ours,
            theirs,
            base,
            document_id: None,
        });
    }
    Ok(out)
}

pub(in super::super) fn index_entry_path(entry: &git2::IndexEntry) -> anyhow::Result<String> {
    let raw = &entry.path;
    if raw.is_empty() {
        anyhow::bail!("empty index entry path");
    }
    if let Ok(cstr) = std::ffi::CStr::from_bytes_with_nul(raw) {
        Ok(cstr
            .to_str()
            .unwrap_or_default()
            .trim_end_matches('\0')
            .to_string())
    } else {
        Ok(String::from_utf8_lossy(raw)
            .trim_end_matches('\0')
            .to_string())
    }
}

pub(in super::super) fn index_entry_stage(entry: &git2::IndexEntry) -> i32 {
    ((entry.flags as u32 >> 12) & 0b11) as i32
}

pub(in super::super) fn as_text_or_binary(
    path: &str,
    data: Option<&Vec<u8>>,
) -> (Option<String>, bool) {
    let Some(bytes) = data else {
        return (None, false);
    };
    match std::str::from_utf8(bytes) {
        Ok(s) => (Some(s.to_string()), false),
        Err(_) => {
            let lower = path.to_ascii_lowercase();
            let looks_text = lower.ends_with(".md")
                || lower.ends_with(".markdown")
                || lower.ends_with(".txt")
                || lower.ends_with(".json")
                || lower.ends_with(".yaml")
                || lower.ends_with(".yml")
                || lower.ends_with(".toml")
                || lower.ends_with(".ini");
            if looks_text {
                let lossy = String::from_utf8_lossy(bytes).to_string();
                return (Some(lossy), false);
            }
            (None, true)
        }
    }
}
