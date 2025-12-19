use std::sync::atomic::{AtomicU64, Ordering};

pub trait MetricsRegistryFacade: Send + Sync {
    fn render(&self) -> String;
}

#[derive(Default)]
pub struct MetricsRegistry {
    storage_projection_success: AtomicU64,
    storage_projection_retry: AtomicU64,
    storage_projection_failure: AtomicU64,
    storage_ingest_success: AtomicU64,
    storage_ingest_retry: AtomicU64,
    storage_ingest_failure: AtomicU64,
    git_rebuild_success: AtomicU64,
    git_rebuild_retry: AtomicU64,
    git_rebuild_failure: AtomicU64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MetricsSnapshot {
    pub storage_projection_success: u64,
    pub storage_projection_retry: u64,
    pub storage_projection_failure: u64,
    pub storage_ingest_success: u64,
    pub storage_ingest_retry: u64,
    pub storage_ingest_failure: u64,
    pub git_rebuild_success: u64,
    pub git_rebuild_retry: u64,
    pub git_rebuild_failure: u64,
}

impl MetricsRegistry {
    pub fn inc_storage_projection_success(&self) {
        self.storage_projection_success
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_storage_projection_retry(&self) {
        self.storage_projection_retry
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_storage_projection_failure(&self) {
        self.storage_projection_failure
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_storage_ingest_success(&self) {
        self.storage_ingest_success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_storage_ingest_retry(&self) {
        self.storage_ingest_retry.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_storage_ingest_failure(&self) {
        self.storage_ingest_failure.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_git_rebuild_success(&self) {
        self.git_rebuild_success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_git_rebuild_retry(&self) {
        self.git_rebuild_retry.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_git_rebuild_failure(&self) {
        self.git_rebuild_failure.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            storage_projection_success: self.storage_projection_success.load(Ordering::Relaxed),
            storage_projection_retry: self.storage_projection_retry.load(Ordering::Relaxed),
            storage_projection_failure: self.storage_projection_failure.load(Ordering::Relaxed),
            storage_ingest_success: self.storage_ingest_success.load(Ordering::Relaxed),
            storage_ingest_retry: self.storage_ingest_retry.load(Ordering::Relaxed),
            storage_ingest_failure: self.storage_ingest_failure.load(Ordering::Relaxed),
            git_rebuild_success: self.git_rebuild_success.load(Ordering::Relaxed),
            git_rebuild_retry: self.git_rebuild_retry.load(Ordering::Relaxed),
            git_rebuild_failure: self.git_rebuild_failure.load(Ordering::Relaxed),
        }
    }

    pub fn render(&self) -> String {
        let snap = self.snapshot();
        format!(
            concat!(
                "# HELP storage_projection_jobs_total Storage projection job outcomes\n",
                "# TYPE storage_projection_jobs_total counter\n",
                "storage_projection_jobs_total{{status=\"success\"}} {sp_success}\n",
                "storage_projection_jobs_total{{status=\"retry\"}} {sp_retry}\n",
                "storage_projection_jobs_total{{status=\"failure\"}} {sp_failure}\n",
                "# HELP storage_ingest_events_total Storage ingest handler outcomes\n",
                "# TYPE storage_ingest_events_total counter\n",
                "storage_ingest_events_total{{status=\"success\"}} {si_success}\n",
                "storage_ingest_events_total{{status=\"retry\"}} {si_retry}\n",
                "storage_ingest_events_total{{status=\"failure\"}} {si_failure}\n",
                "# HELP git_rebuild_jobs_total Git rebuild job outcomes\n",
                "# TYPE git_rebuild_jobs_total counter\n",
                "git_rebuild_jobs_total{{status=\"success\"}} {gr_success}\n",
                "git_rebuild_jobs_total{{status=\"retry\"}} {gr_retry}\n",
                "git_rebuild_jobs_total{{status=\"failure\"}} {gr_failure}\n"
            ),
            sp_success = snap.storage_projection_success,
            sp_retry = snap.storage_projection_retry,
            sp_failure = snap.storage_projection_failure,
            si_success = snap.storage_ingest_success,
            si_retry = snap.storage_ingest_retry,
            si_failure = snap.storage_ingest_failure,
            gr_success = snap.git_rebuild_success,
            gr_retry = snap.git_rebuild_retry,
            gr_failure = snap.git_rebuild_failure,
        )
    }
}

impl MetricsRegistryFacade for MetricsRegistry {
    fn render(&self) -> String {
        MetricsRegistry::render(self)
    }
}
