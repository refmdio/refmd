use std::path::PathBuf;

use async_trait::async_trait;
use tokio::fs;
use tokio::task;
use uuid::Uuid;

use crate::application::dto::git::{
    DiffLine, DiffLineType, DiffResult, GitChangeItem, GitCommitInfo, GitSyncOutcome,
    GitSyncRequestDto, GitWorkspaceStatus,
};
use crate::application::ports::git_repository::UserGitCfg;
use crate::application::ports::git_workspace::GitWorkspacePort;

pub struct GitWorkspaceService {
    uploads_root: PathBuf,
}

impl GitWorkspaceService {
    pub fn new(uploads_root: impl Into<PathBuf>) -> anyhow::Result<Self> {
        Ok(Self {
            uploads_root: uploads_root.into(),
        })
    }

    fn repo_dir(&self, user_id: Uuid) -> PathBuf {
        self.uploads_root.join(user_id.to_string())
    }
}

#[async_trait]
impl GitWorkspacePort for GitWorkspaceService {
    async fn ensure_repository(&self, user_id: Uuid, _default_branch: &str) -> anyhow::Result<()> {
        let dir = self.repo_dir(user_id);
        fs::create_dir_all(&dir).await?;
        task::spawn_blocking(move || -> anyhow::Result<()> {
            let _repo = git2::Repository::open(&dir).or_else(|_| git2::Repository::init(&dir))?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    async fn remove_repository(&self, user_id: Uuid) -> anyhow::Result<()> {
        let dir = self.repo_dir(user_id).join(".git");
        if fs::try_exists(&dir).await.unwrap_or(false) {
            fs::remove_dir_all(&dir).await?;
        }
        Ok(())
    }

    async fn status(&self, user_id: Uuid) -> anyhow::Result<GitWorkspaceStatus> {
        let dir = self.repo_dir(user_id);
        let snapshot = task::spawn_blocking(move || -> anyhow::Result<GitWorkspaceStatus> {
            use git2::{Repository, Status, StatusOptions};
            let repo = match Repository::open(&dir) {
                Ok(r) => r,
                Err(_) => {
                    return Ok(GitWorkspaceStatus {
                        repository_initialized: false,
                        current_branch: None,
                        uncommitted_changes: 0,
                        untracked_files: 0,
                    });
                }
            };
            let current = repo
                .head()
                .ok()
                .and_then(|h| h.shorthand().map(|s| s.to_string()));
            let mut opts = StatusOptions::new();
            opts.include_untracked(true)
                .recurse_untracked_dirs(true)
                .include_ignored(false);
            let mut uncommitted = 0u32;
            let mut untracked = 0u32;
            if let Ok(statuses) = repo.statuses(Some(&mut opts)) {
                for e in statuses.iter() {
                    let s = e.status();
                    if s.contains(Status::WT_NEW) {
                        untracked += 1;
                    } else if s.intersects(
                        Status::WT_MODIFIED
                            | Status::INDEX_MODIFIED
                            | Status::WT_DELETED
                            | Status::INDEX_DELETED
                            | Status::WT_RENAMED
                            | Status::INDEX_RENAMED,
                    ) {
                        uncommitted += 1;
                    }
                }
            }
            Ok(GitWorkspaceStatus {
                repository_initialized: true,
                current_branch: current,
                uncommitted_changes: uncommitted,
                untracked_files: untracked,
            })
        })
        .await??;
        Ok(snapshot)
    }

    async fn list_changes(&self, user_id: Uuid) -> anyhow::Result<Vec<GitChangeItem>> {
        let dir = self.repo_dir(user_id);
        let (changes,): (Vec<GitChangeItem>,) =
            task::spawn_blocking(move || -> anyhow::Result<_> {
                use git2::{Repository, Status, StatusOptions};
                let repo = match Repository::open(&dir) {
                    Ok(r) => r,
                    Err(_) => return Ok((vec![],)),
                };
                let mut opts = StatusOptions::new();
                opts.include_untracked(true)
                    .recurse_untracked_dirs(true)
                    .include_ignored(false);
                let mut out: Vec<GitChangeItem> = Vec::new();
                if let Ok(statuses) = repo.statuses(Some(&mut opts)) {
                    for e in statuses.iter() {
                        let s = e.status();
                        let path = e.path().unwrap_or("").to_string();
                        if path.is_empty() {
                            continue;
                        }
                        let status = if s.contains(Status::WT_NEW) {
                            "untracked"
                        } else if s.intersects(Status::WT_DELETED | Status::INDEX_DELETED) {
                            "deleted"
                        } else if s.intersects(Status::WT_RENAMED | Status::INDEX_RENAMED) {
                            "renamed"
                        } else if s.intersects(
                            Status::WT_MODIFIED
                                | Status::INDEX_MODIFIED
                                | Status::WT_TYPECHANGE
                                | Status::INDEX_TYPECHANGE,
                        ) {
                            "modified"
                        } else {
                            "changed"
                        };
                        out.push(GitChangeItem {
                            path,
                            status: status.to_string(),
                        });
                    }
                }
                Ok((out,))
            })
            .await??;
        Ok(changes)
    }

    async fn working_diff(&self, user_id: Uuid) -> anyhow::Result<Vec<DiffResult>> {
        let dir = self.repo_dir(user_id);
        let (diffs,): (Vec<DiffResult>,) = task::spawn_blocking(move || -> anyhow::Result<_> {
            use git2::Repository;
            let repo = match Repository::open(&dir) {
                Ok(r) => r,
                Err(_) => return Ok((vec![],)),
            };
            let mut opts = git2::DiffOptions::new();
            opts.context_lines(3).include_untracked(false);
            let diff = match repo.diff_index_to_workdir(None, Some(&mut opts)) {
                Ok(d) => d,
                Err(_) => return Ok((vec![],)),
            };
            let out = process_diff(diff)?;
            Ok((out,))
        })
        .await??;
        Ok(diffs)
    }

    async fn commit_diff(
        &self,
        user_id: Uuid,
        from: &str,
        to: &str,
    ) -> anyhow::Result<Vec<DiffResult>> {
        let dir = self.repo_dir(user_id);
        let from = from.to_string();
        let to = to.to_string();
        let (diffs,): (Vec<DiffResult>,) = task::spawn_blocking(move || -> anyhow::Result<_> {
            use git2::Repository;
            let repo = match Repository::open(&dir) {
                Ok(r) => r,
                Err(_) => return Ok((vec![],)),
            };
            let from_obj = match repo.revparse_single(&from) {
                Ok(o) => o,
                Err(_) => return Ok((vec![],)),
            };
            let to_obj = match repo.revparse_single(&to) {
                Ok(o) => o,
                Err(_) => return Ok((vec![],)),
            };
            let from_commit = match from_obj.peel_to_commit() {
                Ok(c) => c,
                Err(_) => return Ok((vec![],)),
            };
            let to_commit = match to_obj.peel_to_commit() {
                Ok(c) => c,
                Err(_) => return Ok((vec![],)),
            };
            let mut opts = git2::DiffOptions::new();
            opts.context_lines(3);
            let diff = match repo.diff_tree_to_tree(
                Some(&from_commit.tree()?),
                Some(&to_commit.tree()?),
                Some(&mut opts),
            ) {
                Ok(d) => d,
                Err(_) => return Ok((vec![],)),
            };
            let out = process_diff(diff)?;
            Ok((out,))
        })
        .await??;
        Ok(diffs)
    }

    async fn history(&self, user_id: Uuid) -> anyhow::Result<Vec<GitCommitInfo>> {
        let dir = self.repo_dir(user_id);
        let commits = task::spawn_blocking(move || -> anyhow::Result<Vec<GitCommitInfo>> {
            use git2::{Oid, Repository};
            let repo = match Repository::open(&dir) {
                Ok(r) => r,
                Err(_) => return Ok(Vec::new()),
            };
            let head = match repo.head() {
                Ok(h) => h,
                Err(_) => return Ok(Vec::new()),
            };
            let target = match head.target() {
                Some(t) => t,
                None => return Ok(Vec::new()),
            };
            let mut revwalk = match repo.revwalk() {
                Ok(w) => w,
                Err(_) => return Ok(Vec::new()),
            };
            let _ = revwalk.push(target);
            let _ = revwalk
                .set_sorting(git2::Sort::TIME | git2::Sort::TOPOLOGICAL | git2::Sort::REVERSE);
            let mut out = Vec::new();
            for oid_res in revwalk {
                let oid: Oid = match oid_res {
                    Ok(o) => o,
                    Err(_) => continue,
                };
                let commit = match repo.find_commit(oid) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let author = commit.author();
                let when = commit.time();
                let seconds = when.seconds();
                let offset = when.offset_minutes();
                let timestamp = seconds - (offset as i64) * 60;
                let time = chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp, 0)
                    .unwrap_or_else(chrono::Utc::now);
                out.push(GitCommitInfo {
                    hash: commit.id().to_string(),
                    message: commit.message().unwrap_or("").to_string(),
                    author_name: author.name().unwrap_or("").to_string(),
                    author_email: author.email().unwrap_or("").to_string(),
                    time,
                });
            }
            Ok(out)
        })
        .await??;
        Ok(commits)
    }

    async fn sync(
        &self,
        user_id: Uuid,
        req: &GitSyncRequestDto,
        cfg: Option<&UserGitCfg>,
    ) -> anyhow::Result<GitSyncOutcome> {
        let dir = self.repo_dir(user_id);
        fs::create_dir_all(&dir).await?;
        let message = req
            .message
            .clone()
            .unwrap_or_else(|| "RefMD sync".to_string());

        let (files_changed, commit_hash) = task::spawn_blocking({
            let dir = dir.clone();
            let message = message.clone();
            move || -> anyhow::Result<(u32, Option<String>)> {
                use git2::{IndexAddOption, Repository, Signature};
                let repo = match Repository::open(&dir) {
                    Ok(r) => r,
                    Err(_) => Repository::init(&dir)?,
                };
                let mut index = repo.index()?;
                index.add_all(["*"].iter(), IndexAddOption::DEFAULT, None)?;
                index.write()?;
                let statuses = repo.statuses(None)?;
                let mut changed = 0u32;
                for e in statuses.iter() {
                    if !e.status().is_empty() {
                        changed += 1;
                    }
                }
                if changed == 0 {
                    return Ok((0, None));
                }
                let tree_oid = index.write_tree()?;
                let tree = repo.find_tree(tree_oid)?;
                let sig = Signature::now("RefMD", "refmd@example.com")?;
                let head = repo.head().ok().and_then(|h| h.target());
                let commit_oid = if let Some(head_oid) = head {
                    let parent = repo.find_commit(head_oid)?;
                    repo.commit(Some("HEAD"), &sig, &sig, &message, &tree, &[&parent])?
                } else {
                    repo.commit(Some("HEAD"), &sig, &sig, &message, &tree, &[])?
                };
                Ok((changed, Some(commit_oid.to_string())))
            }
        })
        .await??;

        if files_changed == 0 {
            return Ok(GitSyncOutcome {
                files_changed,
                commit_hash,
                pushed: false,
                message: "nothing to commit".to_string(),
            });
        }

        let mut pushed = false;
        if let Some(cfg) = cfg {
            if !cfg.repository_url.is_empty() {
                pushed = task::spawn_blocking({
                    let dir = dir.clone();
                    let cfg = cfg.clone();
                    move || -> anyhow::Result<bool> {
                        use git2::{Cred, PushOptions, RemoteCallbacks, Repository};
                        let repo = Repository::open(&dir)?;
                        if repo.find_remote("origin").is_err() {
                            let _ = repo.remote("origin", &cfg.repository_url)?;
                        } else if repo.find_remote("origin")?.url() != Some(&cfg.repository_url) {
                            repo.remote_set_url("origin", &cfg.repository_url)?;
                        }
                        let mut remote = repo.find_remote("origin")?;
                        let mut callbacks = RemoteCallbacks::new();
                        let auth_type = cfg.auth_type.clone().unwrap_or_default();
                        let auth_data = cfg.auth_data.clone();
                        callbacks.credentials(move |_url, username_from_url, _allowed| {
                            if auth_type == "token" {
                                if let Some(token) = auth_data
                                    .as_ref()
                                    .and_then(|v| v.get("token"))
                                    .and_then(|v| v.as_str())
                                {
                                    let user = username_from_url.unwrap_or("x-access-token");
                                    return Cred::userpass_plaintext(user, token);
                                }
                            }
                            if auth_type == "ssh" {
                                if let Some(key) = auth_data
                                    .as_ref()
                                    .and_then(|v| v.get("private_key"))
                                    .and_then(|v| v.as_str())
                                {
                                    let user = username_from_url.unwrap_or("git");
                                    return Cred::ssh_key_from_memory(user, None, key, None);
                                }
                            }
                            Cred::default()
                        });
                        let mut opts = PushOptions::new();
                        opts.remote_callbacks(callbacks);
                        let refspec = format!("HEAD:refs/heads/{}", cfg.branch_name);
                        remote.push(&[&refspec], Some(&mut opts))?;
                        Ok(true)
                    }
                })
                .await
                .unwrap_or(Ok(false))?;
            }
        }

        Ok(GitSyncOutcome {
            files_changed,
            commit_hash,
            pushed,
            message: if pushed {
                "sync completed".to_string()
            } else {
                "commit created".to_string()
            },
        })
    }
}

fn process_diff(diff: git2::Diff<'_>) -> anyhow::Result<Vec<DiffResult>> {
    use std::cell::RefCell;
    use std::rc::Rc;

    let results = Rc::new(RefCell::new(Vec::<DiffResult>::new()));
    let current_file_path = Rc::new(RefCell::new(String::new()));
    let current_diff_result: Rc<RefCell<Option<DiffResult>>> = Rc::new(RefCell::new(None));
    let current_old_line = Rc::new(RefCell::new(0u32));
    let current_new_line = Rc::new(RefCell::new(0u32));

    let results_clone = results.clone();
    let current_file_path_clone = current_file_path.clone();
    let current_diff_result_clone = current_diff_result.clone();
    let current_old_line_clone = current_old_line.clone();
    let current_new_line_clone = current_new_line.clone();

    diff.foreach(
        &mut |delta, _| {
            let file_path = delta
                .new_file()
                .path()
                .or_else(|| delta.old_file().path())
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            let mut current_fp = current_file_path_clone.borrow_mut();
            if file_path != *current_fp {
                if let Some(result) = current_diff_result_clone.borrow_mut().take() {
                    results_clone.borrow_mut().push(result);
                }
                *current_fp = file_path.clone();
                *current_diff_result_clone.borrow_mut() = Some(DiffResult {
                    file_path,
                    diff_lines: Vec::new(),
                    old_content: None,
                    new_content: None,
                });
                *current_old_line_clone.borrow_mut() = 0;
                *current_new_line_clone.borrow_mut() = 0;
            }
            true
        },
        None,
        Some(&mut |_, hunk| {
            *current_old_line.borrow_mut() = hunk.old_start().saturating_sub(1);
            *current_new_line.borrow_mut() = hunk.new_start().saturating_sub(1);
            true
        }),
        Some(&mut |_, _, line| {
            let content = String::from_utf8_lossy(line.content()).to_string();
            if let Some(ref mut diff_result) = *current_diff_result.borrow_mut() {
                match line.origin() {
                    '+' => {
                        *current_new_line.borrow_mut() += 1;
                        diff_result.diff_lines.push(DiffLine {
                            line_type: DiffLineType::Added,
                            old_line_number: None,
                            new_line_number: Some(*current_new_line.borrow()),
                            content: content.trim_end().to_string(),
                        });
                    }
                    '-' => {
                        *current_old_line.borrow_mut() += 1;
                        diff_result.diff_lines.push(DiffLine {
                            line_type: DiffLineType::Deleted,
                            old_line_number: Some(*current_old_line.borrow()),
                            new_line_number: None,
                            content: content.trim_end().to_string(),
                        });
                    }
                    ' ' => {
                        *current_old_line.borrow_mut() += 1;
                        *current_new_line.borrow_mut() += 1;
                        diff_result.diff_lines.push(DiffLine {
                            line_type: DiffLineType::Context,
                            old_line_number: Some(*current_old_line.borrow()),
                            new_line_number: Some(*current_new_line.borrow()),
                            content: content.trim_end().to_string(),
                        });
                    }
                    _ => {}
                }
            }
            true
        }),
    )?;

    if let Some(result) = current_diff_result.borrow_mut().take() {
        results.borrow_mut().push(result);
    }
    Ok(results.borrow().clone())
}
