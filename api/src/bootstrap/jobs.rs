use tokio::task::JoinHandle;

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
        let handle = tokio::spawn(async move { fut.await });
        self.handles.push(JobHandle { name, handle });
    }

    /// Expose handles for inspection or later coordination.
    pub fn handles(&self) -> &[JobHandle] {
        &self.handles
    }
}
