use std::panic::AssertUnwindSafe;

use futures_util::FutureExt;
use tokio::task::JoinHandle;
use tracing::{debug, error, info};

/// Handle to a background task.
pub struct JobHandle {
    pub name: &'static str,
    pub handle: JoinHandle<()>,
}

/// Small registry to keep track of spawned background jobs.
pub struct Jobs {
    handles: Vec<JobHandle>,
}

impl Jobs {
    pub fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    /// Spawn a background task and record its handle.
    pub fn spawn<F>(&mut self, name: &'static str, fut: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let handle = tokio::spawn(async move {
            if let Err(panic) = AssertUnwindSafe(fut).catch_unwind().await {
                error!(?panic, job = name, "background_job_panicked");
            }
        });
        self.handles.push(JobHandle { name, handle });
    }

    /// Expose handles for inspection or later coordination.
    pub fn handles(&self) -> &[JobHandle] {
        &self.handles
    }

    /// Abort all tracked jobs and await their termination.
    pub async fn shutdown(self) {
        for JobHandle { name, handle } in self.handles {
            handle.abort();
            match handle.await {
                Ok(()) => {}
                Err(err) if err.is_cancelled() => {
                    debug!(job = name, "background_job_cancelled");
                }
                Err(err) => {
                    error!(job = name, error = ?err, "background_job_join_failed");
                }
            }
        }
    }
}

/// Wait for Ctrl+C or SIGTERM and log which signal was received.
pub async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("create SIGTERM listener");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown_signal_received: ctrl_c");
            }
            _ = sigterm.recv() => {
                info!("shutdown_signal_received: sigterm");
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        info!("shutdown_signal_received: ctrl_c");
    }
}
