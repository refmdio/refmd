use anyhow::Context;
use sqlx::pool::PoolConnection;
use sqlx::{Pool, Postgres};

/// Simple wrapper for PostgreSQL advisory locks that keeps the connection
/// alive for the duration of the lock.
pub struct AdvisoryLock {
    key: i64,
    conn: PoolConnection<Postgres>,
}

impl AdvisoryLock {
    /// Attempts to acquire the advisory lock identified by `key`.
    /// Returns `Ok(Some(Self))` when the lock was acquired, `Ok(None)` when it
    /// is held by another session.
    pub async fn try_acquire(pool: &Pool<Postgres>, key: i64) -> anyhow::Result<Option<Self>> {
        let mut conn = pool.acquire().await?;
        let acquired: bool = sqlx::query_scalar("select pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut *conn)
            .await
            .context("pg_try_advisory_lock")?;

        if acquired {
            Ok(Some(Self { key, conn }))
        } else {
            drop(conn);
            Ok(None)
        }
    }

    /// Releases the advisory lock. Any error here is converted into anyhow::Error
    /// so callers can log it but continue.
    pub async fn release(self) -> anyhow::Result<()> {
        let mut conn = self.conn;
        let released: bool = sqlx::query_scalar("select pg_advisory_unlock($1)")
            .bind(self.key)
            .fetch_one(&mut *conn)
            .await
            .context("pg_advisory_unlock")?;

        if !released {
            anyhow::bail!("snapshot_lock_was_not_held");
        }
        Ok(())
    }
}
