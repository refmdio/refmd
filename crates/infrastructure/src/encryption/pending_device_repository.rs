//! PostgreSQL pending device repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::encryption::{DeviceId, DeviceType, PendingDevice, PendingDeviceRepository};
use domain::identity::UserId;
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// PostgreSQL pending device repository
#[derive(Clone)]
pub struct PgPendingDeviceRepository {
    pool: PgPool,
}

impl PgPendingDeviceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
pub enum PgPendingDeviceRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("corrupted data: invalid device type: {0}")]
    InvalidDeviceType(String),
}

#[derive(sqlx::FromRow)]
struct PendingDeviceRow {
    id: Uuid,
    user_id: Uuid,
    name: String,
    device_type: String,
    ecdh_public_key: Vec<u8>,
    signing_public_key: Vec<u8>,
    client_nonce: Vec<u8>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl PendingDeviceRow {
    fn try_into_pending_device(self) -> Result<PendingDevice, PgPendingDeviceRepositoryError> {
        let device_type: DeviceType = self
            .device_type
            .parse()
            .map_err(|_| PgPendingDeviceRepositoryError::InvalidDeviceType(self.device_type.clone()))?;

        Ok(PendingDevice {
            id: DeviceId::from_uuid(self.id),
            user_id: UserId::from_uuid(self.user_id),
            name: self.name,
            device_type,
            ecdh_public_key: self.ecdh_public_key,
            signing_public_key: self.signing_public_key,
            client_nonce: self.client_nonce,
            created_at: self.created_at,
            expires_at: self.expires_at,
        })
    }
}

#[async_trait]
impl PendingDeviceRepository for PgPendingDeviceRepository {
    type Error = PgPendingDeviceRepositoryError;

    async fn find_by_id(&self, id: DeviceId) -> Result<Option<PendingDevice>, Self::Error> {
        let row = sqlx::query_as::<_, PendingDeviceRow>(
            r#"
            SELECT id, user_id, name, device_type, ecdh_public_key, signing_public_key,
                   client_nonce, created_at, expires_at
            FROM pending_devices
            WHERE id = $1
            "#,
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into_pending_device()).transpose()
    }

    async fn find_by_user_id(&self, user_id: UserId) -> Result<Vec<PendingDevice>, Self::Error> {
        let rows = sqlx::query_as::<_, PendingDeviceRow>(
            r#"
            SELECT id, user_id, name, device_type, ecdh_public_key, signing_public_key,
                   client_nonce, created_at, expires_at
            FROM pending_devices
            WHERE user_id = $1 AND expires_at > NOW()
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into_pending_device()).collect()
    }

    async fn save(&self, device: &PendingDevice) -> Result<(), Self::Error> {
        sqlx::query(
            r#"
            INSERT INTO pending_devices (id, user_id, name, device_type, ecdh_public_key,
                                        signing_public_key, client_nonce, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (id) DO UPDATE SET
                expires_at = EXCLUDED.expires_at
            "#,
        )
        .bind(device.id.as_uuid())
        .bind(device.user_id.as_uuid())
        .bind(&device.name)
        .bind(device.device_type.as_str())
        .bind(&device.ecdh_public_key)
        .bind(&device.signing_public_key)
        .bind(&device.client_nonce)
        .bind(device.created_at)
        .bind(device.expires_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, id: DeviceId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM pending_devices WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_expired(&self) -> Result<u64, Self::Error> {
        let result = sqlx::query("DELETE FROM pending_devices WHERE expires_at <= NOW()")
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }
}
