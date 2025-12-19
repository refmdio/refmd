use super::super::*;

pub(in super::super) fn extract_host(url: &str) -> Option<String> {
    let s = url.trim();
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let mut parts = s.split('/');
    let host_port = parts.next().unwrap_or("");
    let host = host_port.split(':').next().unwrap_or("");
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

pub(in super::super) fn default_token_username_for(host: Option<&str>) -> &'static str {
    match host {
        Some(h) if h.contains("github") => "x-access-token",
        Some(h) if h.contains("gitlab") => "oauth2",
        Some(h) if h.contains("dev.azure.com") || h.contains("visualstudio.com") => "pat",
        _ => "git",
    }
}

pub(in super::super) fn build_remote_callbacks(cfg: &UserGitCfg) -> RemoteCallbacks<'static> {
    let auth_type = cfg.auth_type;
    let auth_data = cfg.auth_data.clone();
    let host_hint = extract_host(&cfg.repository_url);
    let mut callbacks = RemoteCallbacks::new();
    callbacks.credentials(
        move |_url, username_from_url, _allowed| match auth_type {
            Some(domain::git::auth::GitAuthType::Token) => {
                if let Some(token) = auth_data
                    .as_ref()
                    .and_then(|v| v.get("token"))
                    .and_then(|v| v.as_str())
                {
                    let user = username_from_url
                        .unwrap_or(default_token_username_for(host_hint.as_deref()));
                    Cred::userpass_plaintext(user, token)
                } else {
                    Cred::default()
                }
            }
            Some(domain::git::auth::GitAuthType::Ssh) => {
                if let Some(key) = auth_data
                    .as_ref()
                    .and_then(|v| v.get("private_key"))
                    .and_then(|v| v.as_str())
                {
                    let user = username_from_url.unwrap_or("git");
                    let passphrase = auth_data
                        .as_ref()
                        .and_then(|v| v.get("passphrase"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty());
                    let trimmed = key.trim();
                    if trimmed.starts_with("v1:") {
                        return Err(GitError::from_str(
                            "failed to decrypt stored SSH key; check ENCRYPTION_KEY and re-save credentials",
                        ));
                    }
                    if trimmed.contains("BEGIN OPENSSH PRIVATE KEY") {
                        return Err(GitError::from_str(
                            "OpenSSH private key format is not supported; provide PEM (BEGIN RSA/EC PRIVATE KEY)",
                        ));
                    }
                    let needs_passphrase = trimmed.contains("ENCRYPTED");
                    if needs_passphrase && passphrase.is_none() {
                        return Err(GitError::from_str(
                            "SSH private key is encrypted; passphrase is required",
                        ));
                    }
                    Cred::ssh_key_from_memory(user, None, trimmed, passphrase)
                } else {
                    Cred::default()
                }
            }
            None => Cred::default(),
        },
    );
    callbacks.certificate_check(|_, _| Ok(CertificateCheckStatus::CertificateOk));
    callbacks
}

pub(in super::super) fn prepare_remote<'repo>(
    repo: &'repo Repository,
    cfg: &UserGitCfg,
) -> anyhow::Result<git2::Remote<'repo>> {
    let mut remote = match repo.find_remote("origin") {
        Ok(remote) => remote,
        Err(_) => repo.remote("origin", &cfg.repository_url)?,
    };
    if remote.url() != Some(cfg.repository_url.as_str()) {
        repo.remote_set_url("origin", &cfg.repository_url)?;
        remote = repo.find_remote("origin")?;
    }
    Ok(remote)
}

pub(in super::super) fn fetch_remote_head(
    repo: &Repository,
    cfg: &UserGitCfg,
    branch: &str,
) -> anyhow::Result<Option<git2::Oid>> {
    let mut remote = prepare_remote(repo, cfg)?;
    let callbacks = build_remote_callbacks(cfg);
    let mut fetch_options = FetchOptions::new();
    fetch_options.remote_callbacks(callbacks);
    let refspec = format!("refs/heads/{branch}:refs/remotes/origin/{branch}");
    remote
        .fetch(&[&refspec], Some(&mut fetch_options), None)
        .map_err(map_git_http_error)?;
    let reference_name = format!("refs/remotes/origin/{branch}");
    match repo.find_reference(&reference_name) {
        Ok(reference) => Ok(reference.target()),
        Err(err) if err.code() == git2::ErrorCode::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

pub(in super::super) fn perform_push(
    repo: &Repository,
    cfg: &UserGitCfg,
    branch: &str,
    commit_oid: git2::Oid,
    force: bool,
) -> anyhow::Result<bool> {
    let ref_name = format!("refs/heads/{}", branch);
    repo.reference(&ref_name, commit_oid, true, "update branch for sync")?;

    let mut remote = prepare_remote(repo, cfg)?;
    let callbacks = build_remote_callbacks(cfg);
    let mut push_options = PushOptions::new();
    push_options.remote_callbacks(callbacks);
    let refspec = if force {
        format!("+refs/heads/{0}:refs/heads/{0}", branch)
    } else {
        format!("refs/heads/{0}:refs/heads/{0}", branch)
    };
    remote
        .push(&[&refspec], Some(&mut push_options))
        .map_err(map_git_http_error)?;
    Ok(true)
}

pub(in super::super) fn map_git_http_error(err: git2::Error) -> anyhow::Error {
    if err.class() == ErrorClass::Http {
        let msg = err.to_string().to_lowercase();
        if msg.contains("status code: 401")
            || msg.contains("status code: 407")
            || msg.contains("redirect")
        {
            // Avoid leaking raw libgit2 error strings to the user; normalize to a short tag.
            return anyhow!("git_http_auth_redirect");
        }
        if msg.contains("status code: 403") || msg.contains("status code: 404") {
            return anyhow!("git_http_not_found");
        }
    }
    err.into()
}
