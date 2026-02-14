//! Encryption module - KEK/DEK management
//!
//! This module provides commands and queries for managing:
//! - WorkspaceEncryptedKey (KEK) - Workspace key encryption keys
//! - DocumentEncryptedKey (DEK) - Document encryption keys

pub mod commands;
pub(crate) mod key_version_util;
pub mod queries;
pub mod services;

pub use commands::*;
pub use queries::*;
pub use services::*;
