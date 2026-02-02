//! Infrastructure layer - External system integrations
//!
//! This layer contains:
//! - Repository implementations: SQLx-based data access
//! - External service integrations: S3, OAuth, etc.
//! - Configuration: Environment variables, config files

// Re-export for convenience
pub use application;
pub use domain;

// TODO: Add repository implementations as features are implemented
// TODO: Add external service clients
// TODO: Add configuration module
