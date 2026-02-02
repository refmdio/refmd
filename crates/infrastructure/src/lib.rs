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
pub mod document;
pub mod encryption;
pub mod identity;
pub mod workspace;

pub use database::{DatabaseConfig, create_pool};
pub use identity::PgRegistrationService;
