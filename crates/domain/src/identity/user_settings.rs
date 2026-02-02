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
const MIN_FONT_SIZE: i32 = 10;
const MAX_FONT_SIZE: i32 = 32;

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

    /// Update theme
    pub fn set_theme(&mut self, theme: Theme) {
        self.theme = theme;
        self.updated_at = Utc::now();
    }

    /// Update locale
    pub fn set_locale(&mut self, locale: Locale) {
        self.locale = locale;
        self.updated_at = Utc::now();
    }

    /// Toggle vim mode
    pub fn set_vim_mode(&mut self, enabled: bool) {
        self.editor_vim_mode = enabled;
        self.updated_at = Utc::now();
    }

    /// Set font size (clamped to valid range)
    pub fn set_font_size(&mut self, size: i32) {
        self.editor_font_size = size.clamp(MIN_FONT_SIZE, MAX_FONT_SIZE);
        self.updated_at = Utc::now();
    }
}
