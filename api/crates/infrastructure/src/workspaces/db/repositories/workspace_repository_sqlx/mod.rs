use crate::core::db::PgPool;

mod helpers;
mod repo;

pub struct SqlxWorkspaceRepository {
    pub pool: PgPool,
}

impl SqlxWorkspaceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
