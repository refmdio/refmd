//! Identity domain module
//!
//! Contains User, Session, and authentication-related entities

pub mod repository;
pub mod session;
pub mod user;
pub mod user_settings;
pub mod value_objects;

pub use repository::{SessionRepository, UserRepository, UserSettingsRepository};
pub use session::{Session, SessionId};
pub use user::{User, UserId};
pub use user_settings::UserSettings;
pub use value_objects::{Email, EmailError, Locale, Theme};
