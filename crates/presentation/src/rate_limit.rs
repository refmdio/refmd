//! Rate limiting configuration
//!
//! Uses tower-governor for rate limiting on sensitive endpoints.

use std::{sync::Arc, time::Duration};

use axum::http::Request;
use tower_governor::{GovernorError, governor::GovernorConfigBuilder, key_extractor::KeyExtractor};

/// Key extractor that uses client IP from X-Forwarded-For or X-Real-IP header
#[derive(Clone)]
pub struct ClientIpKeyExtractor;

impl KeyExtractor for ClientIpKeyExtractor {
    type Key = String;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        crate::client_ip::extract_client_ip(req.headers()).ok_or_else(|| GovernorError::Other {
            code: axum::http::StatusCode::BAD_REQUEST,
            msg: Some("unable to determine client IP".to_string()),
            headers: None,
        })
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
pub fn create_auth_rate_limit_config() -> Result<Arc<RateLimitConfig>, anyhow::Error> {
    Ok(Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(ClientIpKeyExtractor)
            .per_second(10)
            .burst_size(20)
            .finish()
            .ok_or_else(|| anyhow::anyhow!("failed to create auth rate limit config"))?,
    ))
}

/// Create stricter rate limiting configuration for registration
///
/// Limit: 3 requests per minute (1 per 20 seconds, burst of 3)
pub fn create_register_rate_limit_config() -> Result<Arc<RateLimitConfig>, anyhow::Error> {
    Ok(Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(ClientIpKeyExtractor)
            .period(Duration::from_secs(20))
            .burst_size(3)
            .finish()
            .ok_or_else(|| anyhow::anyhow!("failed to create register rate limit config"))?,
    ))
}

/// Create rate limiting configuration for device registration
///
/// Limit: 5 requests per minute (1 per 12 seconds, burst of 5)
pub fn create_device_rate_limit_config() -> Result<Arc<RateLimitConfig>, anyhow::Error> {
    Ok(Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(ClientIpKeyExtractor)
            .period(Duration::from_secs(12))
            .burst_size(5)
            .finish()
            .ok_or_else(|| anyhow::anyhow!("failed to create device rate limit config"))?,
    ))
}

