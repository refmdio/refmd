//! PostgreSQL user settings repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::identity::{Locale, UserId, UserSettings, UserSettingsRepository};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// PostgreSQL user settings repository
#[derive(Clone)]
pub struct PgUserSettingsRepository {
    pool: PgPool,
}

impl PgUserSettingsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
#[error("database error: {0}")]
pub struct PgUserSettingsRepositoryError(#[from] sqlx::Error);

/// Database row for user settings
#[derive(sqlx::FromRow)]
struct UserSettingsRow {
    user_id: Uuid,
    theme: String,
    locale: String,
    editor_vim_mode: bool,
    editor_font_size: i32,
    updated_at: DateTime<Utc>,
}

impl From<UserSettingsRow> for UserSettings {
    fn from(row: UserSettingsRow) -> Self {
        Self {
            user_id: UserId::from_uuid(row.user_id),
            theme: row.theme.parse().unwrap_or_default(),
            locale: Locale::new(row.locale),
            editor_vim_mode: row.editor_vim_mode,
            editor_font_size: row.editor_font_size,
            updated_at: row.updated_at,
        }
    }
}

#[async_trait]
impl UserSettingsRepository for PgUserSettingsRepository {
    type Error = PgUserSettingsRepositoryError;

    async fn find_by_user_id(&self, user_id: UserId) -> Result<Option<UserSettings>, Self::Error> {
        let row = sqlx::query_as::<_, UserSettingsRow>(
            r#"
            SELECT user_id, theme, locale, editor_vim_mode, editor_font_size, updated_at
            FROM user_settings
            WHERE user_id = $1
            "#,
        )
        .bind(user_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(UserSettings::from))
    }

    async fn save(&self, settings: &UserSettings) -> Result<(), Self::Error> {
        sqlx::query(
            r#"
            INSERT INTO user_settings (user_id, theme, locale, editor_vim_mode, editor_font_size, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (user_id) DO UPDATE SET
                theme = EXCLUDED.theme,
                locale = EXCLUDED.locale,
                editor_vim_mode = EXCLUDED.editor_vim_mode,
                editor_font_size = EXCLUDED.editor_font_size,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(settings.user_id.as_uuid())
        .bind(settings.theme.as_str())
        .bind(settings.locale.as_str())
        .bind(settings.editor_vim_mode)
        .bind(settings.editor_font_size)
        .bind(settings.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, user_id: UserId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM user_settings WHERE user_id = $1")
            .bind(user_id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
