impl GitWorkspaceService {
    fn compute_deltas(
        &self,
        current: &HashMap<String, FileSnapshot>,
        previous: &HashMap<String, String>,
    ) -> FileDeltaSummary {
        let mut added = Vec::new();
        let mut modified = Vec::new();
        let mut deleted = Vec::new();

        for (path, snapshot) in current.iter() {
            match previous.get(path) {
                None => added.push(path.clone()),
                Some(prev_hash) if prev_hash != &snapshot.hash => modified.push(path.clone()),
                _ => {}
            }
        }

        for path in previous.keys() {
            if !current.contains_key(path) {
                deleted.push(path.clone());
            }
        }

        FileDeltaSummary {
            added,
            modified,
            deleted,
        }
    }
}
