//! Redis connection pool for cluster mode
//!
//! Provides Redis connection management for HA deployments.
//! Used for challenge cache and device event bus when CLUSTER_ENABLED=true.

use redis::Client;
use redis::aio::ConnectionManager;
use thiserror::Error;

/// Redis configuration
#[derive(Debug, Clone)]
pub struct RedisConfig {
    /// Redis connection URL (e.g., redis://localhost:6379)
    pub url: String,
}

impl RedisConfig {
    /// Create config from environment variables
    ///
    /// Required: REDIS_URL
    pub fn from_env() -> Option<Self> {
        std::env::var("REDIS_URL").ok().map(|url| Self { url })
    }
}

/// Redis connection pool using ConnectionManager for automatic reconnection
#[derive(Clone)]
pub struct RedisPool {
    manager: ConnectionManager,
}

impl RedisPool {
    /// Get a connection from the pool
    pub fn connection(&self) -> ConnectionManager {
        self.manager.clone()
    }

    /// Check if Redis is healthy
    pub async fn health_check(&self) -> Result<(), RedisError> {
        let mut conn = self.manager.clone();
        redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .map_err(RedisError::Connection)?;
        Ok(())
    }
}

/// Redis-related errors
#[derive(Debug, Error)]
pub enum RedisError {
    #[error("Redis connection error: {0}")]
    Connection(#[from] redis::RedisError),

    #[error("Redis configuration error: {0}")]
    Config(String),
}

/// Create a Redis connection pool
pub async fn create_redis_pool(config: &RedisConfig) -> Result<RedisPool, RedisError> {
    let client =
        Client::open(config.url.as_str()).map_err(|e| RedisError::Config(e.to_string()))?;

    let manager = ConnectionManager::new(client)
        .await
        .map_err(RedisError::Connection)?;

    // Verify connection
    let pool = RedisPool { manager };
    pool.health_check().await?;

    tracing::info!("Redis connection pool created successfully");
    Ok(pool)
}
