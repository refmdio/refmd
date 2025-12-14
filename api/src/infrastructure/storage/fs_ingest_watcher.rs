use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use notify::event::{EventKind, ModifyKind, RenameMode};
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::{Map, Value};
use tokio::sync::mpsc::{self, UnboundedSender};
use tracing::{debug, error, warn};
use uuid::Uuid;

use crate::application::ports::storage_ingest_queue::{StorageIngestKind, StorageIngestQueue};
use crate::application::services::storage_ingest::normalize_repo_path;
use crate::application::utils::hash::sha256_hex;
use crate::domain::workspaces::permissions::PermissionSet;

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
                    self.enqueue_rename(&event.paths[0], &event.paths[1])
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
        let Some(clean_repo) = normalize_repo_path(&repo_path) else {
            warn!(
                user_id = %user_id,
                repo_path = repo_path,
                "fs_ingest_invalid_repo_path"
            );
            return Ok(());
        };
        let (content_hash, payload) = if matches!(kind, StorageIngestKind::Upsert) {
            self.capture_file_metadata(path, &clean_repo).await
        } else {
            (None, None)
        };
        let permissions = PermissionSet::all().to_vec();
        self.queue
            .enqueue_event(
                user_id,
                user_id,
                None,
                &clean_repo,
                &self.backend_name,
                kind,
                content_hash.as_deref(),
                payload,
                &permissions,
            )
            .await?;
        debug!(
            user_id = %user_id,
            repo_path = clean_repo,
            kind = ?kind,
            "fs_ingest_event_enqueued"
        );
        Ok(())
    }

    async fn enqueue_rename(&self, from: &Path, to: &Path) -> anyhow::Result<()> {
        let Some((from_user, from_repo)) = self.parse_repo_path(from) else {
            return Ok(());
        };
        let Some((to_user, to_repo)) = self.parse_repo_path(to) else {
            return Ok(());
        };
        if from_user != to_user {
            return Ok(());
        }
        let Some(clean_from) = normalize_repo_path(&from_repo) else {
            warn!(repo_path = from_repo, "fs_ingest_invalid_repo_path");
            return Ok(());
        };
        let Some(clean_to) = normalize_repo_path(&to_repo) else {
            warn!(repo_path = to_repo, "fs_ingest_invalid_repo_path");
            return Ok(());
        };
        let (content_hash, payload) = self.capture_file_metadata(to, &clean_to).await;
        let payload = attach_previous_path(payload, &clean_from);
        let permissions = PermissionSet::all().to_vec();
        self.queue
            .enqueue_event(
                to_user,
                to_user,
                None,
                &clean_to,
                &self.backend_name,
                StorageIngestKind::Upsert,
                content_hash.as_deref(),
                payload,
                &permissions,
            )
            .await?;
        debug!(
            user_id = %to_user,
            repo_path = clean_to,
            previous_path = clean_from,
            "fs_ingest_rename_event_enqueued"
        );
        Ok(())
    }

    async fn capture_file_metadata(
        &self,
        path: &Path,
        repo_path: &str,
    ) -> (Option<String>, Option<Value>) {
        match tokio::fs::read(path).await {
            Ok(bytes) => {
                let hash = sha256_hex(&bytes);
                let payload = serde_json::json!({
                    "file_kind": file_kind(repo_path),
                    "is_text": repo_path.ends_with(".md"),
                    "size": bytes.len(),
                });
                (Some(hash), Some(payload))
            }
            Err(err) => {
                warn!(error = ?err, repo_path = repo_path, "fs_ingest_metadata_failed");
                (None, None)
            }
        }
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

fn file_kind(repo_path: &str) -> &'static str {
    if repo_path.contains("/attachments/") {
        "attachment"
    } else {
        "document"
    }
}

fn attach_previous_path(payload: Option<Value>, previous_repo_path: &str) -> Option<Value> {
    let mut map = match payload {
        Some(Value::Object(obj)) => obj,
        Some(other) => match other.as_object() {
            Some(obj) => obj.clone(),
            None => Map::new(),
        },
        None => Map::new(),
    };
    map.insert(
        "previous_path".to_string(),
        Value::String(previous_repo_path.to_string()),
    );
    Some(Value::Object(map))
}
