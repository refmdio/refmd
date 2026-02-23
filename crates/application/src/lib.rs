//! Application layer - Use cases and application services
//!
//! This layer contains:
//! - Use Cases: Application-specific business rules (Command/Query)
//! - DTOs: Data transfer objects between layers
//! - Application Services: Orchestration of use cases
//!
//! ## DI Convention
//! - Domain repositories: generic type params with `?Sized` bound (`Arc<DR>` where `DR: Repository + ?Sized`)
//! - Application services/stores (ChallengeStore, TransferNonceStore, etc.): `Arc<dyn Trait>`

pub mod document;
pub mod dto;
pub mod encryption;
pub mod events;
pub mod identity;
pub mod trust_transfer;
pub mod types;
pub(crate) mod util;
pub mod workspace;
pub mod workspace_events;
