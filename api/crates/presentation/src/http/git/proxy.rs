use axum::{
    extract::{Path, Query},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use std::collections::HashMap;

/// Git HTTP protocol CORS proxy
/// Forwards requests from isomorphic-git to remote Git servers
/// Backend does not process Git operations, only relays network requests

/// HTTPS Git proxy - forwards GET/POST requests to remote
pub async fn proxy_git_https(
    method: Method,
    Path(remote_path): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ProxyError> {
    // Build remote URL with query string
    let remote_url = if query.is_empty() {
        format!("https://{}", remote_path)
    } else {
        let query_string: String = query
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");
        format!("https://{}?{}", remote_path, query_string)
    };

    // Security: only allow known Git hosting providers
    let allowed_hosts = ["github.com", "gitlab.com", "bitbucket.org"];
    let host = remote_path
        .split('/')
        .next()
        .ok_or(ProxyError::InvalidUrl)?;

    if !allowed_hosts
        .iter()
        .any(|h| host == *h || host.ends_with(&format!(".{}", h)))
    {
        return Err(ProxyError::HostNotAllowed);
    }

    let client = reqwest::Client::builder()
        .user_agent("RefMD-Git-Proxy/1.0")
        .build()
        .map_err(|_| ProxyError::ClientError)?;

    let mut req_builder = match method {
        Method::GET => client.get(&remote_url),
        Method::POST => client.post(&remote_url),
        _ => return Err(ProxyError::MethodNotAllowed),
    };

    // Forward necessary headers
    if let Some(auth) = headers.get("authorization") {
        req_builder = req_builder.header("Authorization", auth.to_str().unwrap_or(""));
    }
    if let Some(ct) = headers.get("content-type") {
        req_builder = req_builder.header("Content-Type", ct.to_str().unwrap_or(""));
    }
    if let Some(git_protocol) = headers.get("git-protocol") {
        req_builder = req_builder.header("Git-Protocol", git_protocol.to_str().unwrap_or(""));
    }

    if !body.is_empty() {
        req_builder = req_builder.body(body.to_vec());
    }

    let response = req_builder
        .send()
        .await
        .map_err(|_| ProxyError::UpstreamError)?;

    let status = StatusCode::from_u16(response.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut response_headers = HeaderMap::new();

    if let Some(ct) = response.headers().get("content-type") {
        response_headers.insert("content-type", ct.clone());
    }
    if let Some(cl) = response.headers().get("content-length") {
        response_headers.insert("content-length", cl.clone());
    }
    if let Some(cache) = response.headers().get("cache-control") {
        response_headers.insert("cache-control", cache.clone());
    }

    // Add CORS headers
    response_headers.insert(
        "access-control-allow-origin",
        HeaderValue::from_static("*"),
    );
    response_headers.insert(
        "access-control-allow-methods",
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    response_headers.insert(
        "access-control-allow-headers",
        HeaderValue::from_static("Authorization, Content-Type, Git-Protocol"),
    );

    let body_bytes = response
        .bytes()
        .await
        .map_err(|_| ProxyError::UpstreamError)?;

    Ok((status, response_headers, body_bytes).into_response())
}

/// CORS preflight request handler
pub async fn proxy_git_https_options() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        "access-control-allow-origin",
        HeaderValue::from_static("*"),
    );
    headers.insert(
        "access-control-allow-methods",
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        "access-control-allow-headers",
        HeaderValue::from_static("Authorization, Content-Type, Git-Protocol"),
    );
    headers.insert("access-control-max-age", HeaderValue::from_static("86400"));

    (StatusCode::NO_CONTENT, headers)
}

#[derive(Debug)]
pub enum ProxyError {
    InvalidUrl,
    HostNotAllowed,
    MethodNotAllowed,
    ClientError,
    UpstreamError,
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ProxyError::InvalidUrl => (StatusCode::BAD_REQUEST, "Invalid URL"),
            ProxyError::HostNotAllowed => (StatusCode::FORBIDDEN, "Host not allowed"),
            ProxyError::MethodNotAllowed => (StatusCode::METHOD_NOT_ALLOWED, "Method not allowed"),
            ProxyError::ClientError => (StatusCode::INTERNAL_SERVER_ERROR, "Client error"),
            ProxyError::UpstreamError => (StatusCode::BAD_GATEWAY, "Upstream error"),
        };

        (status, message).into_response()
    }
}
