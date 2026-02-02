//! Infrastructure layer - External system integrations
//!
//! This layer contains:
//! - Repository implementations: SQLx-based data access
//! - External service integrations: S3, OAuth, etc.
//! - Configuration: Environment variables, config files

// Re-export for convenience
pub use application;
pub use domain;

pub mod database;
pub mod identity;

pub use database::{create_pool, DatabaseConfig};
