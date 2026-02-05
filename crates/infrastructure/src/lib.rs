//! Infrastructure layer - External system integrations
//!
//! This layer contains:
//! - Repository implementations: SQLx-based data access
//! - External service integrations: S3, OAuth, Redis, etc.
//! - Configuration: Environment variables, config files

// Re-export for convenience
pub use application;
pub use domain;

pub mod challenge_store;
pub mod database;
pub mod device_events;
pub mod document;
pub mod encryption;
pub mod identity;
pub mod redis;
pub mod workspace;

pub use challenge_store::RedisChallengeStore;
pub use database::{DatabaseConfig, create_pool};
pub use sqlx::PgPool;
pub use device_events::RedisDeviceEventBus;
pub use identity::PgRegistrationService;
pub use redis::{RedisConfig, RedisError, RedisPool, create_redis_pool};
