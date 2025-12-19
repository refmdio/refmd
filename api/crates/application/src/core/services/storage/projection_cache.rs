use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use uuid::Uuid;

#[derive(Debug)]
pub struct RecentProjectionCache {
    ttl: Duration,
    entries: Mutex<HashMap<(Uuid, String), CacheEntry>>,
}

#[derive(Debug)]
struct CacheEntry {
    hash: String,
    recorded_at: Instant,
}

impl RecentProjectionCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn record(&self, workspace_id: Uuid, repo_path: &str, content_hash: &str) {
        let mut guard = self
            .entries
            .lock()
            .expect("recent projection cache poisoned");
        let now = Instant::now();
        guard.retain(|_, entry| now.duration_since(entry.recorded_at) <= self.ttl);
        guard.insert(
            (workspace_id, repo_path.to_string()),
            CacheEntry {
                hash: content_hash.to_string(),
                recorded_at: now,
            },
        );
    }

    pub fn is_recent_match(&self, workspace_id: Uuid, repo_path: &str, content_hash: &str) -> bool {
        let mut guard = self
            .entries
            .lock()
            .expect("recent projection cache poisoned");
        let now = Instant::now();
        guard.retain(|_, entry| now.duration_since(entry.recorded_at) <= self.ttl);
        guard
            .get(&(workspace_id, repo_path.to_string()))
            .map(|entry| entry.hash == content_hash)
            .unwrap_or(false)
    }
}
