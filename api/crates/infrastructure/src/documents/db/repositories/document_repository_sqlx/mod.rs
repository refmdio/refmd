use crate::core::db::PgPool;

mod helpers;
mod repo;

#[cfg(test)]
mod tests;

pub struct SqlxDocumentRepository {
    pub pool: PgPool,
}

impl SqlxDocumentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
