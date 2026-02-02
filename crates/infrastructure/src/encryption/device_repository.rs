//! PostgreSQL device repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::encryption::{Device, DeviceId, DeviceRepository, DeviceType};
use domain::identity::UserId;
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// PostgreSQL device repository
#[derive(Clone)]
pub struct PgDeviceRepository {
    pool: PgPool,
}

impl PgDeviceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
pub enum PgDeviceRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("corrupted data: invalid device type: {0}")]
    InvalidDeviceType(String),
}

#[derive(sqlx::FromRow)]
struct DeviceRow {
    id: Uuid,
    user_id: Uuid,
    name: String,
    device_type: String,
    ecdh_public_key: Vec<u8>,
    signing_public_key: Vec<u8>,
    identity_signature: Vec<u8>,
    client_nonce: Vec<u8>,
    last_seen_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl DeviceRow {
    fn try_into_device(self) -> Result<Device, PgDeviceRepositoryError> {
        let device_type: DeviceType = self
            .device_type
            .parse()
            .map_err(|_| PgDeviceRepositoryError::InvalidDeviceType(self.device_type.clone()))?;

        Ok(Device {
            id: DeviceId::from_uuid(self.id),
            user_id: UserId::from_uuid(self.user_id),
            name: self.name,
            device_type,
            ecdh_public_key: self.ecdh_public_key,
            signing_public_key: self.signing_public_key,
            identity_signature: self.identity_signature,
            client_nonce: self.client_nonce,
            last_seen_at: self.last_seen_at,
            created_at: self.created_at,
            revoked_at: self.revoked_at,
        })
    }
}

#[async_trait]
impl DeviceRepository for PgDeviceRepository {
    type Error = PgDeviceRepositoryError;

    async fn find_by_id(&self, id: DeviceId) -> Result<Option<Device>, Self::Error> {
        let row = sqlx::query_as::<_, DeviceRow>(
            r#"
            SELECT id, user_id, name, device_type, ecdh_public_key, signing_public_key,
                   identity_signature, client_nonce, last_seen_at, created_at, revoked_at
            FROM devices
            WHERE id = $1
            "#,
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into_device()).transpose()
    }

    async fn find_by_user_id(&self, user_id: UserId) -> Result<Vec<Device>, Self::Error> {
        let rows = sqlx::query_as::<_, DeviceRow>(
            r#"
            SELECT id, user_id, name, device_type, ecdh_public_key, signing_public_key,
                   identity_signature, client_nonce, last_seen_at, created_at, revoked_at
            FROM devices
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into_device()).collect()
    }

    async fn find_active_by_user_id(&self, user_id: UserId) -> Result<Vec<Device>, Self::Error> {
        let rows = sqlx::query_as::<_, DeviceRow>(
            r#"
            SELECT id, user_id, name, device_type, ecdh_public_key, signing_public_key,
                   identity_signature, client_nonce, last_seen_at, created_at, revoked_at
            FROM devices
            WHERE user_id = $1 AND revoked_at IS NULL
            ORDER BY last_seen_at DESC
            "#,
        )
        .bind(user_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into_device()).collect()
    }

    async fn save(&self, device: &Device) -> Result<(), Self::Error> {
        sqlx::query(
            r#"
            INSERT INTO devices (id, user_id, name, device_type, ecdh_public_key, signing_public_key,
                                identity_signature, client_nonce, last_seen_at, created_at, revoked_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                last_seen_at = EXCLUDED.last_seen_at,
                revoked_at = EXCLUDED.revoked_at
            "#,
        )
        .bind(device.id.as_uuid())
        .bind(device.user_id.as_uuid())
        .bind(&device.name)
        .bind(device.device_type.as_str())
        .bind(&device.ecdh_public_key)
        .bind(&device.signing_public_key)
        .bind(&device.identity_signature)
        .bind(&device.client_nonce)
        .bind(device.last_seen_at)
        .bind(device.created_at)
        .bind(device.revoked_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, id: DeviceId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM devices WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
