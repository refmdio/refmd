//! WebSocket real-time collaboration module
//!
//! Handles WebSocket connections for document editing,
//! broadcasting updates/snapshots/ephemeral messages between clients.

pub mod connection_store;
pub mod handler;
pub mod messages;
pub mod signature;

pub use connection_store::DocumentConnectionStore;
