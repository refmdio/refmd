impl GitWorkspaceService {
    fn sync_build_change_sets(
        use_full_scan: bool,
        dirty_rows: &[DirtyRow],
        previous_index: &HashMap<String, String>,
    ) -> (BTreeMap<String, DirtyUpsert>, BTreeSet<String>) {
        if use_full_scan {
            return (BTreeMap::new(), BTreeSet::new());
        }

        let mut upserts: BTreeMap<String, DirtyUpsert> = BTreeMap::new();
        let mut deletes: BTreeSet<String> = BTreeSet::new();

        for row in dirty_rows {
            match row.op.as_str() {
                "upsert" => {
                    upserts.insert(
                        row.path.clone(),
                        DirtyUpsert {
                            is_text: row.is_text,
                            content_hash: row.content_hash.clone(),
                        },
                    );
                    deletes.remove(&row.path);
                }
                "delete" => {
                    upserts.remove(&row.path);
                    deletes.insert(row.path.clone());
                }
                _ => {}
            }
        }

        upserts.retain(|path, u| {
            !matches!(
                (&u.content_hash, previous_index.get(path)),
                (Some(hnew), Some(hprev)) if hnew == hprev
            )
        });

        (upserts, deletes)
    }
}
