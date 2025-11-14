use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use notify::event::{EventKind, ModifyKind, RenameMode};
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc::{self, UnboundedSender};
use tracing::{debug, error, warn};
use uuid::Uuid;

use crate::application::ports::storage_ingest_queue::{StorageIngestKind, StorageIngestQueue};

pub struct FsIngestWatcher {
    uploads_root: PathBuf,
    queue: Arc<dyn StorageIngestQueue>,
    backend_name: String,
}

impl FsIngestWatcher {
    pub fn new(
        uploads_root: PathBuf,
        queue: Arc<dyn StorageIngestQueue>,
        backend_name: &str,
    ) -> Self {
        Self {
            uploads_root,
            queue,
            backend_name: backend_name.to_string(),
        }
    }

    pub async fn run(self: Arc<Self>) {
        loop {
            if let Err(err) = self.run_once().await {
                error!(error = ?err, "fs_ingest_watcher_loop_failed");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }

    async fn run_once(&self) -> notify::Result<()> {
        let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
        let mut watcher = self.create_watcher(tx)?;
        watcher.watch(self.uploads_root.as_path(), RecursiveMode::Recursive)?;
        while let Some(event) = rx.recv().await {
            if let Err(err) = self.process_event(event).await {
                warn!(error = ?err, "fs_ingest_watcher_event_failed");
            }
        }
        Ok(())
    }

    fn create_watcher(&self, sender: UnboundedSender<Event>) -> notify::Result<RecommendedWatcher> {
        RecommendedWatcher::new(
            move |res| {
                if let Ok(event) = res {
                    let _ = sender.send(event);
                }
            },
            Config::default(),
        )
    }

    async fn process_event(&self, event: Event) -> anyhow::Result<()> {
        let kind = classify_event(&event.kind);
        match kind {
            EventDisposition::Ignore => return Ok(()),
            EventDisposition::Split => {
                if event.paths.len() == 2 {
                    self.enqueue_path(&event.paths[0], StorageIngestKind::Delete)
                        .await?;
                    self.enqueue_path(&event.paths[1], StorageIngestKind::Upsert)
                        .await?;
                } else {
                    for path in event.paths {
                        self.enqueue_path(&path, StorageIngestKind::Upsert).await?;
                    }
                }
            }
            EventDisposition::Kind(k) => {
                for path in event.paths {
                    self.enqueue_path(&path, k).await?;
                }
            }
        }
        Ok(())
    }

    async fn enqueue_path(&self, path: &Path, kind: StorageIngestKind) -> anyhow::Result<()> {
        let Some((user_id, repo_path)) = self.parse_repo_path(path) else {
            return Ok(());
        };
        if repo_path.is_empty() {
            return Ok(());
        }
        self.queue
            .enqueue_event(user_id, &repo_path, &self.backend_name, kind, None, None)
            .await?;
        debug!(
            user_id = %user_id,
            repo_path = repo_path,
            kind = ?kind,
            "fs_ingest_event_enqueued"
        );
        Ok(())
    }

    fn parse_repo_path(&self, path: &Path) -> Option<(Uuid, String)> {
        let relative = path.strip_prefix(&self.uploads_root).ok()?;
        let mut components = relative.components();
        let owner_component = components.next()?;
        let owner_str = owner_component.as_os_str().to_str()?;
        let owner_id = Uuid::parse_str(owner_str).ok()?;
        let repo_path = components
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        Some((owner_id, repo_path))
    }
}

enum EventDisposition {
    Ignore,
    Split,
    Kind(StorageIngestKind),
}

fn classify_event(kind: &EventKind) -> EventDisposition {
    match kind {
        EventKind::Create(_) => EventDisposition::Kind(StorageIngestKind::Upsert),
        EventKind::Modify(ModifyKind::Data(_)) => EventDisposition::Kind(StorageIngestKind::Upsert),
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => EventDisposition::Split,
        EventKind::Modify(ModifyKind::Name(RenameMode::To)) => {
            EventDisposition::Kind(StorageIngestKind::Upsert)
        }
        EventKind::Modify(ModifyKind::Name(RenameMode::From)) => {
            EventDisposition::Kind(StorageIngestKind::Delete)
        }
        EventKind::Remove(_) => EventDisposition::Kind(StorageIngestKind::Delete),
        _ => EventDisposition::Ignore,
    }
}
