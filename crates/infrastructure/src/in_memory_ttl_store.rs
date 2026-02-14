//! Generic in-memory TTL store utilities
//!
//! Provides periodic cleanup logic shared by all in-memory stores.

use std::{
    sync::RwLock,
    time::{Duration, Instant},
};

/// Periodic cleanup tracker.
///
/// Shared by all in-memory TTL stores to avoid duplicating the
/// "check interval → purge expired" logic.
pub struct TtlCleanup {
    cleanup_interval: Duration,
    last_cleanup: RwLock<Instant>,
}

impl TtlCleanup {
    pub fn new(cleanup_interval: Duration) -> Self {
        Self {
            cleanup_interval,
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Run `purge_fn` if enough time has elapsed since the last cleanup.
    pub fn maybe_cleanup(&self, purge_fn: impl FnOnce()) {
        let now = Instant::now();
        let should_cleanup = {
            let last = self.last_cleanup.read().unwrap_or_else(|e| e.into_inner());
            now.duration_since(*last) > self.cleanup_interval
        };

        if should_cleanup {
            purge_fn();
            let mut last = self.last_cleanup.write().unwrap_or_else(|e| e.into_inner());
            *last = now;
        }
    }
}
