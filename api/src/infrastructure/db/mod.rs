use sqlx::{Pool, Postgres};

pub type PgPool = Pool<Postgres>;

pub async fn connect_pool(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await?;
    Ok(pool)
}

pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    // Uses compile-time embedded migrations under ./migrations
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

pub mod repositories;
