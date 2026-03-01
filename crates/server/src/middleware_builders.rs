//! Middleware builder functions
//!
//! Constructs CORS and security headers middleware layers.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::http::{HeaderName, HeaderValue, Method, Request, Response, header};
use tower::Layer;
use tower::Service;
use tower_http::cors::CorsLayer;

// =============================================================================
// SecurityHeadersLayer — a single concrete type regardless of header count
// =============================================================================

/// A middleware layer that sets security response headers.
///
/// Unlike a `ServiceBuilder<Stack<…>>` chain, this is a single concrete type
/// that does not change when headers are added or removed.
#[derive(Clone)]
pub struct SecurityHeadersLayer {
    headers: Arc<[(HeaderName, HeaderValue)]>,
}

impl SecurityHeadersLayer {
    pub fn new(enable_swagger: bool) -> Self {
        let csp_value = if enable_swagger {
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'",
            )
        } else {
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'")
        };

        let headers: Vec<(HeaderName, HeaderValue)> = vec![
            (header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
            (header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
            (header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000; includeSubDomains")),
            (header::REFERRER_POLICY, HeaderValue::from_static("strict-origin-when-cross-origin")),
            (HeaderName::from_static("permissions-policy"), HeaderValue::from_static("geolocation=(), microphone=(), camera=()")),
            (header::CONTENT_SECURITY_POLICY, csp_value),
        ];

        Self { headers: headers.into() }
    }
}

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersService {
            inner,
            headers: self.headers.clone(),
        }
    }
}

/// Service wrapper that injects security headers into every response.
#[derive(Clone)]
pub struct SecurityHeadersService<S> {
    inner: S,
    headers: Arc<[(HeaderName, HeaderValue)]>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SecurityHeadersService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let headers = self.headers.clone();
        let future = self.inner.call(req);
        Box::pin(async move {
            let mut response = future.await?;
            for (name, value) in headers.iter() {
                response.headers_mut().insert(name.clone(), value.clone());
            }
            Ok(response)
        })
    }
}

// =============================================================================
// CORS
// =============================================================================

/// Parse the `CORS_ORIGINS` environment variable into a list of origin strings.
///
/// Returns the validated list of allowed origins. Rejects wildcards (incompatible
/// with credentials). Used by both CORS middleware and CSWSH WebSocket protection.
pub fn parse_cors_origins() -> Result<Vec<String>, anyhow::Error> {
    let cors_origins =
        std::env::var("CORS_ORIGINS").unwrap_or_else(|_| "http://localhost:3000".to_string());

    for origin in cors_origins.split(',') {
        if origin.trim() == "*" {
            anyhow::bail!(
                "CORS_ORIGINS contains '*' which is not allowed with credentials. Specify explicit origins (e.g., 'http://localhost:3000')."
            );
        }
    }

    let origins: Vec<String> = cors_origins
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if origins.is_empty() {
        anyhow::bail!(
            "CORS_ORIGINS contains no valid origins. Specify at least one valid origin URL."
        );
    }

    Ok(origins)
}

/// Build the CORS layer from the `CORS_ORIGINS` environment variable.
///
/// Reads and validates `CORS_ORIGINS` (comma-separated list of allowed origins),
/// rejects wildcards (incompatible with credentials), and constructs a `CorsLayer`
/// that includes the PoP (Proof of Possession) headers used for device authentication.
pub fn build_cors(
    pop_device_id: &HeaderName,
    pop_challenge: &HeaderName,
    pop_signature: &HeaderName,
    allowed_origins: &[String],
) -> Result<CorsLayer, anyhow::Error> {
    let origins: Vec<_> = allowed_origins
        .iter()
        .filter_map(|s| {
            match s.parse() {
                Ok(origin) => Some(origin),
                Err(_) => {
                    tracing::warn!("Ignoring invalid CORS origin: {:?}", s);
                    None
                }
            }
        })
        .collect();

    // Ensure at least one valid origin was parsed
    if origins.is_empty() {
        anyhow::bail!(
            "CORS_ORIGINS contains no valid origins. Specify at least one valid origin URL."
        );
    }

    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::COOKIE,
            pop_device_id.clone(),
            pop_challenge.clone(),
            pop_signature.clone(),
        ])
        .expose_headers([
            pop_device_id.clone(),
            pop_challenge.clone(),
            pop_signature.clone(),
        ])
        .allow_credentials(true);

    Ok(cors)
}

/// Build the security headers middleware layer.
///
/// Constructs a [`SecurityHeadersLayer`] that sets standard security response
/// headers (X-Content-Type-Options, X-Frame-Options, HSTS, Referrer-Policy,
/// Permissions-Policy, and Content-Security-Policy). The CSP is relaxed when
/// Swagger UI is enabled to allow inline scripts/styles required by Swagger.
pub fn build_security_headers(enable_swagger: bool) -> SecurityHeadersLayer {
    SecurityHeadersLayer::new(enable_swagger)
}
