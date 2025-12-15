use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::task_local;

task_local! {
    static SUPPRESS_GIT_DIRTY: bool;
}

// Global counter to suppress dirty tracking across tasks (e.g., filesystem watchers triggered by bulk writes).
static GLOBAL_SUPPRESS_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Guard that decrements the global suppression counter when dropped.
pub struct GlobalSuppressGuard;

impl Drop for GlobalSuppressGuard {
    fn drop(&mut self) {
        GLOBAL_SUPPRESS_COUNT
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some(v.saturating_sub(1))
            })
            .ok();
    }
}

/// Returns true when dirty tracking should be skipped for the current task.
pub fn dirty_tracking_suppressed() -> bool {
    if GLOBAL_SUPPRESS_COUNT.load(Ordering::SeqCst) > 0 {
        return true;
    }
    SUPPRESS_GIT_DIRTY.try_with(|v| *v).unwrap_or(false)
}

/// Run a future with git dirty tracking suppressed for storage writes.
pub async fn suppress_git_dirty<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    SUPPRESS_GIT_DIRTY.scope(true, fut).await
}

/// Increment the global suppression counter for the lifetime of the returned guard.
pub fn suppress_git_dirty_global() -> GlobalSuppressGuard {
    GLOBAL_SUPPRESS_COUNT.fetch_add(1, Ordering::SeqCst);
    GlobalSuppressGuard
}
