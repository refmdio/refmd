//! Domain layer - Core business logic and entities
//!
//! This layer contains:
//! - Entities: Core business objects with identity
//! - Value Objects: Immutable objects defined by their attributes
//! - Domain Events: Events that occur within the domain
//! - Repository Traits: Interfaces for data access (implemented in infrastructure)
//! - Domain Services: Business logic that doesn't belong to a single entity

pub mod document;
pub mod encryption;
pub mod file;
pub mod git;
pub mod identity;
pub mod plugin;
pub mod sharing;
pub mod workspace;
