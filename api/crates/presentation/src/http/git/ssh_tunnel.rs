use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use ssh2::Session;
use std::io::{Read, Write};
use std::net::TcpStream;

use crate::context::AppContext;

/// SSH tunnel for Git protocol
/// Relays Git protocol data over SSH to remote servers
/// Used for isomorphic-git SSH support

#[derive(Debug, Deserialize)]
pub struct SshTunnelRequest {
    /// Git host (e.g., "github.com")
    pub host: String,
    /// Repository path (e.g., "user/repo.git")
    pub repo: String,
    /// Git service: "git-upload-pack" (fetch/clone) or "git-receive-pack" (push)
    pub service: String,
    /// SSH private key (PEM format)
    pub private_key: String,
    /// Optional passphrase for encrypted private key
    pub passphrase: Option<String>,
    /// Git protocol data to send
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct SshTunnelResponse {
    /// Response data from Git server
    pub data: Vec<u8>,
}

pub async fn tunnel_git_ssh(
    State(_ctx): State<AppContext>,
    Json(req): Json<SshTunnelRequest>,
) -> Result<Json<SshTunnelResponse>, SshTunnelError> {
    // Validate service
    if req.service != "git-upload-pack" && req.service != "git-receive-pack" {
        return Err(SshTunnelError::InvalidService);
    }

    // Security: only allow known Git hosting providers
    let allowed_hosts = ["github.com", "gitlab.com", "bitbucket.org"];
    if !allowed_hosts.contains(&req.host.as_str()) {
        return Err(SshTunnelError::HostNotAllowed);
    }

    // Run SSH operation in blocking task
    let result = tokio::task::spawn_blocking(move || {
        execute_ssh_tunnel(req)
    })
    .await
    .map_err(|_| SshTunnelError::InternalError)??;

    Ok(Json(result))
}

fn execute_ssh_tunnel(req: SshTunnelRequest) -> Result<SshTunnelResponse, SshTunnelError> {
    // Connect to SSH server
    let tcp = TcpStream::connect(format!("{}:22", req.host))
        .map_err(|_| SshTunnelError::ConnectionFailed)?;

    let mut session = Session::new().map_err(|_| SshTunnelError::SessionError)?;
    session.set_tcp_stream(tcp);
    session
        .handshake()
        .map_err(|_| SshTunnelError::HandshakeFailed)?;

    // Authenticate with private key
    let passphrase = req.passphrase.as_deref();
    session
        .userauth_pubkey_memory("git", None, &req.private_key, passphrase)
        .map_err(|_| SshTunnelError::AuthFailed)?;

    if !session.authenticated() {
        return Err(SshTunnelError::AuthFailed);
    }

    // Execute Git command
    let command = format!("{} '{}'", req.service, req.repo);
    let mut channel = session
        .channel_session()
        .map_err(|_| SshTunnelError::ChannelError)?;

    channel
        .exec(&command)
        .map_err(|_| SshTunnelError::ExecFailed)?;

    // Send Git protocol data
    if !req.data.is_empty() {
        channel
            .write_all(&req.data)
            .map_err(|_| SshTunnelError::WriteError)?;
        channel.flush().map_err(|_| SshTunnelError::WriteError)?;
    }

    // Signal end of input
    channel
        .send_eof()
        .map_err(|_| SshTunnelError::WriteError)?;

    // Read response
    let mut response_data = Vec::new();
    channel
        .read_to_end(&mut response_data)
        .map_err(|_| SshTunnelError::ReadError)?;

    // Wait for channel to close
    channel
        .wait_close()
        .map_err(|_| SshTunnelError::ChannelError)?;

    Ok(SshTunnelResponse {
        data: response_data,
    })
}

#[derive(Debug)]
pub enum SshTunnelError {
    InvalidService,
    HostNotAllowed,
    ConnectionFailed,
    SessionError,
    HandshakeFailed,
    AuthFailed,
    ChannelError,
    ExecFailed,
    WriteError,
    ReadError,
    InternalError,
}

impl IntoResponse for SshTunnelError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            SshTunnelError::InvalidService => (StatusCode::BAD_REQUEST, "Invalid Git service"),
            SshTunnelError::HostNotAllowed => (StatusCode::FORBIDDEN, "Host not allowed"),
            SshTunnelError::ConnectionFailed => (StatusCode::BAD_GATEWAY, "Connection failed"),
            SshTunnelError::SessionError => (StatusCode::INTERNAL_SERVER_ERROR, "Session error"),
            SshTunnelError::HandshakeFailed => (StatusCode::BAD_GATEWAY, "SSH handshake failed"),
            SshTunnelError::AuthFailed => (StatusCode::UNAUTHORIZED, "SSH authentication failed"),
            SshTunnelError::ChannelError => (StatusCode::INTERNAL_SERVER_ERROR, "Channel error"),
            SshTunnelError::ExecFailed => (StatusCode::BAD_GATEWAY, "Command execution failed"),
            SshTunnelError::WriteError => (StatusCode::BAD_GATEWAY, "Write error"),
            SshTunnelError::ReadError => (StatusCode::BAD_GATEWAY, "Read error"),
            SshTunnelError::InternalError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
        };

        (status, message).into_response()
    }
}
