//! PostgreSQL device repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::encryption::{Device, DeviceId, DeviceRepository, DeviceType};
use domain::identity::UserId;
use uuid::Uuid;

pg_repo_struct!(PgDeviceRepository);
pg_repo_error!(PgDeviceRepositoryError, InvalidDeviceType(String));

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
        let row = sqlx::query_as!(
            DeviceRow,
            r#"
            SELECT id, user_id, name, device_type, ecdh_public_key, signing_public_key,
                   identity_signature, client_nonce, last_seen_at, created_at, revoked_at
            FROM devices
            WHERE id = $1
            "#,
            id.as_uuid()
        )
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into_device()).transpose()
    }

    async fn find_by_user_id(&self, user_id: UserId) -> Result<Vec<Device>, Self::Error> {
        let rows = sqlx::query_as!(
            DeviceRow,
            r#"
            SELECT id, user_id, name, device_type, ecdh_public_key, signing_public_key,
                   identity_signature, client_nonce, last_seen_at, created_at, revoked_at
            FROM devices
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
            user_id.as_uuid()
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into_device()).collect()
    }

    async fn find_active_by_user_id(&self, user_id: UserId) -> Result<Vec<Device>, Self::Error> {
        let rows = sqlx::query_as!(
            DeviceRow,
            r#"
            SELECT id, user_id, name, device_type, ecdh_public_key, signing_public_key,
                   identity_signature, client_nonce, last_seen_at, created_at, revoked_at
            FROM devices
            WHERE user_id = $1 AND revoked_at IS NULL
            ORDER BY last_seen_at DESC
            "#,
            user_id.as_uuid()
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into_device()).collect()
    }

    async fn find_active_by_signing_pub_key(
        &self,
        signing_pub_key: &[u8],
    ) -> Result<Option<Device>, Self::Error> {
        let row = sqlx::query_as!(
            DeviceRow,
            r#"
            SELECT id, user_id, name, device_type, ecdh_public_key, signing_public_key,
                   identity_signature, client_nonce, last_seen_at, created_at, revoked_at
            FROM devices
            WHERE signing_public_key = $1 AND revoked_at IS NULL
            "#,
            signing_pub_key
        )
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into_device()).transpose()
    }

    async fn save(&self, device: &Device) -> Result<(), Self::Error> {
        sqlx::query!(
            r#"
            INSERT INTO devices (id, user_id, name, device_type, ecdh_public_key, signing_public_key,
                                identity_signature, client_nonce, last_seen_at, created_at, revoked_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                last_seen_at = EXCLUDED.last_seen_at,
                revoked_at = EXCLUDED.revoked_at
            "#,
            device.id.as_uuid(),
            device.user_id.as_uuid(),
            &device.name,
            device.device_type.as_str(),
            &device.ecdh_public_key,
            &device.signing_public_key,
            &device.identity_signature,
            &device.client_nonce,
            device.last_seen_at,
            device.created_at,
            device.revoked_at as Option<DateTime<Utc>>
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, id: DeviceId) -> Result<(), Self::Error> {
        sqlx::query!(
            "DELETE FROM devices WHERE id = $1",
            id.as_uuid()
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
