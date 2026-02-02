//! Encryption module - KEK/DEK management
//!
//! This module provides commands and queries for managing:
//! - WorkspaceEncryptedKey (KEK) - Workspace key encryption keys
//! - DocumentEncryptedKey (DEK) - Document encryption keys

pub mod commands;
pub mod queries;

pub use commands::*;
pub use queries::*;
