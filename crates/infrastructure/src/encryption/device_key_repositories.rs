//! PostgreSQL device key repository implementations

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::encryption::{
    DeviceEncryptedUMK, DeviceEncryptedUMKRepository, DeviceId, DeviceRevocationEvent,
    DeviceRevocationEventRepository,
};
use domain::identity::UserId;
use uuid::Uuid;

// ============ DeviceRevocationEvent Repository ============

pg_repo_struct!(PgDeviceRevocationEventRepository);
pg_repo_error!(PgDeviceRevocationEventRepositoryError);

#[derive(sqlx::FromRow)]
struct DeviceRevocationEventRow {
    user_id: Uuid,
    device_id: Uuid,
    revoked_at: i64,
    revoked_by_device_id: Uuid,
    signature: Vec<u8>,
    created_at: DateTime<Utc>,
}

impl From<DeviceRevocationEventRow> for DeviceRevocationEvent {
    fn from(row: DeviceRevocationEventRow) -> Self {
        Self {
            user_id: UserId::from_uuid(row.user_id),
            device_id: DeviceId::from_uuid(row.device_id),
            revoked_at: row.revoked_at,
            revoked_by_device_id: DeviceId::from_uuid(row.revoked_by_device_id),
            signature: row.signature,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl DeviceRevocationEventRepository for PgDeviceRevocationEventRepository {
    type Error = PgDeviceRevocationEventRepositoryError;

    async fn find_by_user_and_device(
        &self,
        user_id: UserId,
        device_id: DeviceId,
    ) -> Result<Option<DeviceRevocationEvent>, Self::Error> {
        let row = sqlx::query_as!(
            DeviceRevocationEventRow,
            r#"
            SELECT user_id, device_id, revoked_at, revoked_by_device_id, signature, created_at
            FROM device_revocation_events
            WHERE user_id = $1 AND device_id = $2
            "#,
            user_id.as_uuid(),
            device_id.as_uuid(),
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(DeviceRevocationEvent::from))
    }

    async fn find_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Vec<DeviceRevocationEvent>, Self::Error> {
        let rows = sqlx::query_as!(
            DeviceRevocationEventRow,
            r#"
            SELECT user_id, device_id, revoked_at, revoked_by_device_id, signature, created_at
            FROM device_revocation_events
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
            user_id.as_uuid(),
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(DeviceRevocationEvent::from).collect())
    }

    async fn save(&self, event: &DeviceRevocationEvent) -> Result<(), Self::Error> {
        sqlx::query!(
            r#"
            INSERT INTO device_revocation_events (
                user_id, device_id, revoked_at, revoked_by_device_id, signature, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (user_id, device_id) DO NOTHING
            "#,
            event.user_id.as_uuid(),
            event.device_id.as_uuid(),
            event.revoked_at,
            event.revoked_by_device_id.as_uuid(),
            &event.signature,
            event.created_at,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

// ============ DeviceEncryptedUMK Repository ============

pg_repo_struct!(PgDeviceEncryptedUMKRepository);
pg_repo_error!(PgDeviceEncryptedUMKRepositoryError);

#[derive(sqlx::FromRow)]
struct DeviceEncryptedUMKRow {
    user_id: Uuid,
    device_id: Uuid,
    sender_device_id: Uuid,
    encrypted_umk: Vec<u8>,
    nonce: Vec<u8>,
    created_at: DateTime<Utc>,
}

impl From<DeviceEncryptedUMKRow> for DeviceEncryptedUMK {
    fn from(row: DeviceEncryptedUMKRow) -> Self {
        Self {
            user_id: UserId::from_uuid(row.user_id),
            device_id: DeviceId::from_uuid(row.device_id),
            sender_device_id: DeviceId::from_uuid(row.sender_device_id),
            encrypted_umk: row.encrypted_umk,
            nonce: row.nonce,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl DeviceEncryptedUMKRepository for PgDeviceEncryptedUMKRepository {
    type Error = PgDeviceEncryptedUMKRepositoryError;

    async fn find_by_user_and_device(
        &self,
        user_id: UserId,
        device_id: DeviceId,
    ) -> Result<Option<DeviceEncryptedUMK>, Self::Error> {
        let row = sqlx::query_as!(
            DeviceEncryptedUMKRow,
            r#"
            SELECT user_id, device_id, sender_device_id, encrypted_umk, nonce, created_at
            FROM device_encrypted_umks
            WHERE user_id = $1 AND device_id = $2
            "#,
            user_id.as_uuid(),
            device_id.as_uuid(),
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(DeviceEncryptedUMK::from))
    }

    async fn save(&self, umk: &DeviceEncryptedUMK) -> Result<(), Self::Error> {
        sqlx::query!(
            r#"
            INSERT INTO device_encrypted_umks (
                user_id, device_id, sender_device_id, encrypted_umk, nonce, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (user_id, device_id) DO UPDATE SET
                sender_device_id = EXCLUDED.sender_device_id,
                encrypted_umk = EXCLUDED.encrypted_umk,
                nonce = EXCLUDED.nonce
            "#,
            umk.user_id.as_uuid(),
            umk.device_id.as_uuid(),
            umk.sender_device_id.as_uuid(),
            &umk.encrypted_umk,
            &umk.nonce,
            umk.created_at,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, user_id: UserId, device_id: DeviceId) -> Result<(), Self::Error> {
        sqlx::query!(
            "DELETE FROM device_encrypted_umks WHERE user_id = $1 AND device_id = $2",
            user_id.as_uuid(),
            device_id.as_uuid(),
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_by_user_id(&self, user_id: UserId) -> Result<(), Self::Error> {
        sqlx::query!(
            "DELETE FROM device_encrypted_umks WHERE user_id = $1",
            user_id.as_uuid(),
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
