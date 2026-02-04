//! Identity query handlers

mod get_current_user;
mod get_recovery_data;
mod get_salt;
mod get_user;

pub use get_current_user::*;
pub use get_recovery_data::*;
pub use get_salt::*;
pub use get_user::*;
