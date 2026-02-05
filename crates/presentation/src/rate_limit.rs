//! Rate limiting configuration
//!
//! Uses tower-governor for rate limiting on sensitive endpoints.

use std::{sync::Arc, time::Duration};

use axum::{
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
};
use tower_governor::{GovernorError, governor::GovernorConfigBuilder, key_extractor::KeyExtractor};

/// Key extractor that uses client IP from X-Forwarded-For or X-Real-IP header
#[derive(Clone)]
pub struct ClientIpKeyExtractor;

impl KeyExtractor for ClientIpKeyExtractor {
    type Key = String;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        // Try X-Forwarded-For first (for proxied requests)
        if let Some(forwarded_for) = req.headers().get("X-Forwarded-For") {
            if let Ok(value) = forwarded_for.to_str() {
                // Take the first IP in the chain (original client)
                if let Some(client_ip) = value.split(',').next() {
                    return Ok(client_ip.trim().to_string());
                }
            }
        }

        // Fall back to X-Real-IP
        if let Some(real_ip) = req.headers().get("X-Real-IP") {
            if let Ok(value) = real_ip.to_str() {
                return Ok(value.trim().to_string());
            }
        }

        // Default fallback IP (shouldn't happen in production with proper proxy config)
        Ok("unknown".to_string())
    }
}

/// Type alias for the governor config with our custom key extractor
pub type RateLimitConfig = tower_governor::governor::GovernorConfig<
    ClientIpKeyExtractor,
    governor::middleware::NoOpMiddleware,
>;

/// Create rate limiting configuration for auth endpoints
///
/// Default: 10 requests per second with burst of 20
pub fn create_auth_rate_limit_config() -> Arc<RateLimitConfig> {
    Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(ClientIpKeyExtractor)
            .per_second(10)
            .burst_size(20)
            .finish()
            .expect("failed to create rate limit config"),
    )
}

/// Create stricter rate limiting configuration for registration
///
/// Limit: 3 requests per minute (1 per 20 seconds, burst of 3)
pub fn create_register_rate_limit_config() -> Arc<RateLimitConfig> {
    Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(ClientIpKeyExtractor)
            .period(Duration::from_secs(20))
            .burst_size(3)
            .finish()
            .expect("failed to create rate limit config"),
    )
}

/// Create rate limiting configuration for device registration
///
/// Limit: 5 requests per minute (1 per 12 seconds, burst of 5)
pub fn create_device_rate_limit_config() -> Arc<RateLimitConfig> {
    Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(ClientIpKeyExtractor)
            .period(Duration::from_secs(12))
            .burst_size(5)
            .finish()
            .expect("failed to create rate limit config"),
    )
}

/// Response when rate limit is exceeded
pub fn rate_limit_error_response(error: GovernorError) -> Response {
    let retry_after = match &error {
        GovernorError::TooManyRequests { wait_time, .. } => Some(*wait_time),
        _ => None,
    };

    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        serde_json::json!({
            "error": "too many requests",
            "retry_after_secs": retry_after
        })
        .to_string(),
    )
        .into_response();

    if let Some(secs) = retry_after {
        response
            .headers_mut()
            .insert("Retry-After", secs.to_string().parse().unwrap());
    }

    response
}
