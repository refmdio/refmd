//! Infrastructure layer - External system integrations
//!
//! This layer contains:
//! - Repository implementations: SQLx-based data access
//! - External service integrations: S3, OAuth, Redis, etc.
//! - Configuration: Environment variables, config files

#[macro_use]
mod nonce_store_macros;

/// Generate a `PgPool`-wrapper struct with a `new()` constructor.
///
/// ```ignore
/// pg_repo_struct!(PgUserRepository);
/// // expands to:
/// // #[derive(Clone)]
/// // pub struct PgUserRepository { pool: PgPool }
/// // impl PgUserRepository { pub fn new(pool: PgPool) -> Self { Self { pool } } }
/// ```
macro_rules! pg_repo_struct {
    ($name:ident) => {
        #[derive(Clone)]
        pub struct $name {
            pool: sqlx::PgPool,
        }

        impl $name {
            pub fn new(pool: sqlx::PgPool) -> Self {
                Self { pool }
            }
        }
    };
}

/// Generate a repository error enum with `Database(sqlx::Error)` and optional extra variants.
///
/// Extra variants can be plain `Variant(Type)` or `Variant(#[from] Type)` for auto `From` impl.
///
/// ```ignore
/// pg_repo_error!(PgUserRepositoryError);
/// pg_repo_error!(PgWorkspaceRepositoryError, InvalidSlug(String));
/// pg_repo_error!(PgKeyRepositoryError, InvalidKeyVersion(#[from] InvalidKeyVersion));
/// ```
macro_rules! pg_repo_error {
    // Internal rule: generate From impl for #[from] variants
    (@from_impl $name:ident, $variant:ident, #[from] $ty:ty) => {
        impl From<$ty> for $name {
            fn from(e: $ty) -> Self {
                Self::$variant(e)
            }
        }
    };
    // Internal rule: no-op for plain variants
    (@from_impl $name:ident, $variant:ident, $ty:ty) => {};

    ($name:ident $(, $variant:ident( $($inner:tt)+ ) )* $(,)?) => {
        #[derive(Debug)]
        pub enum $name {
            Database(sqlx::Error),
            $( $variant( pg_repo_error!(@strip_from $($inner)+) ), )*
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::Database(e) => write!(f, "database error: {e}"),
                    $( Self::$variant(e) => write!(f, "{}: {e}", stringify!($variant)), )*
                }
            }
        }

        impl std::error::Error for $name {}

        impl From<sqlx::Error> for $name {
            fn from(e: sqlx::Error) -> Self {
                Self::Database(e)
            }
        }

        $( pg_repo_error!(@from_impl $name, $variant, $($inner)+); )*
    };

    // Internal rule: strip #[from] attribute, return just the type
    (@strip_from #[from] $ty:ty) => { $ty };
    (@strip_from $ty:ty) => { $ty };
}

pub mod challenge_store;
pub mod database;
pub mod device_events;
pub mod document;
pub mod encryption;
pub mod identity;
pub mod in_memory_challenge_store;
pub mod in_memory_device_event_bus;
pub mod in_memory_workspace_event_bus;
mod in_memory_nonce_map;
pub mod in_memory_recovery_challenge_store;
pub mod in_memory_transfer_stores;
pub mod in_memory_ttl_store;
pub mod recovery_challenge_store;
pub mod redis;
mod redis_nonce_ops;
pub mod transfer_nonce_store;
pub mod transfer_state_store;
pub mod workspace;
pub mod workspace_event_bus;

pub use challenge_store::RedisChallengeStore;
pub use database::{DatabaseConfig, create_pool};
pub use device_events::RedisDeviceEventBus;
pub use identity::PgRegistrationService;
pub use in_memory_challenge_store::InMemoryChallengeStore;
pub use in_memory_device_event_bus::InMemoryDeviceEventBus;
pub use in_memory_workspace_event_bus::InMemoryWorkspaceEventBus;
pub use workspace_event_bus::RedisWorkspaceEventBus;
pub use in_memory_recovery_challenge_store::InMemoryRecoveryChallengeStore;
pub use in_memory_transfer_stores::{InMemoryTransferNonceStore, InMemoryTransferStateStore};
pub use recovery_challenge_store::RedisRecoveryChallengeStore;
pub use redis::{RedisConfig, RedisError, RedisPool, create_redis_pool};
pub use sqlx::PgPool;
pub use transfer_nonce_store::RedisTransferNonceStore;
pub use transfer_state_store::RedisTransferStateStore;
