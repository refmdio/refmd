//! Document command handlers

mod archive_document;
mod create_document;
mod create_update;
mod delete_document;
mod update_document;

pub use archive_document::*;
pub use create_document::*;
pub use create_update::*;
pub use delete_document::*;
pub use update_document::*;
