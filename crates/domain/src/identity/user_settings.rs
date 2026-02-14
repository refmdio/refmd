//! UserSettings entity

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::user::UserId;
use super::value_objects::{Locale, Theme};

/// UserSettings entity (1:1 with User)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSettings {
    pub user_id: UserId,
    pub theme: Theme,
    pub locale: Locale,
    pub editor_vim_mode: bool,
    pub editor_font_size: i32,
    pub updated_at: DateTime<Utc>,
}

/// Default font size
const DEFAULT_FONT_SIZE: i32 = 14;

impl UserSettings {
    /// Create default settings for a user
    pub fn new(user_id: UserId) -> Self {
        Self {
            user_id,
            theme: Theme::default(),
            locale: Locale::default(),
            editor_vim_mode: false,
            editor_font_size: DEFAULT_FONT_SIZE,
            updated_at: Utc::now(),
        }
    }
}
