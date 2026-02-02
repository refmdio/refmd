//! Application layer - Use cases and application services
//!
//! This layer contains:
//! - Use Cases: Application-specific business rules (Command/Query)
//! - DTOs: Data transfer objects between layers
//! - Application Services: Orchestration of use cases

// Re-export domain for convenience
pub use domain;

pub mod document;
pub mod identity;
pub mod workspace;
