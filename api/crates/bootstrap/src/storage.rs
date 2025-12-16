use std::sync::Arc;

use anyhow::Context;


use application::ports::storage_port::{StorageProjectionPort, StorageResolverPort};
use application::ports::storage_reconcile_backend::StorageReconcileBackend;
use crate::config::{Config, StorageBackend};
use infrastructure::db::PgPool;
use infrastructure::storage::s3::S3StorageConfig;
use infrastructure::storage::s3::S3StoragePort;
use infrastructure::storage::{
    FsReconcileBackend, PgStorageProjectionQueue, S3ReconcileBackend,
};

pub type StoragePorts = (
    Arc<dyn StorageResolverPort>,
    Arc<dyn StorageProjectionPort>,
    Arc<dyn StorageReconcileBackend>,
    bool,
);

pub async fn build_storage_ports(cfg: &Config, pool: &PgPool) -> anyhow::Result<StoragePorts> {
    let uploads_root = std::path::PathBuf::from(&cfg.storage_root);
    let ports = match cfg.storage_backend {
        StorageBackend::Filesystem => {
            let port = Arc::new(infrastructure::storage::port_impl::FsStoragePort {
                pool: pool.clone(),
                uploads_root: uploads_root.clone(),
            });
            let backend: Arc<dyn StorageReconcileBackend> =
                FsReconcileBackend::new(uploads_root) as Arc<dyn StorageReconcileBackend>;
            (
                port.clone() as Arc<dyn StorageResolverPort>,
                port as Arc<dyn StorageProjectionPort>,
                backend,
                false,
            )
        }
        StorageBackend::S3 => {
            let s3_settings = S3StorageConfig {
                uploads_root: uploads_root.clone(),
                bucket: cfg
                    .s3_bucket
                    .clone()
                    .context("S3_BUCKET must be configured when using S3 storage backend")?,
                region: cfg.s3_region.clone(),
                endpoint: cfg.s3_endpoint.clone(),
                access_key: cfg.s3_access_key.clone(),
                secret_key: cfg.s3_secret_key.clone(),
                use_path_style: cfg.s3_use_path_style,
            };
            let port = Arc::new(S3StoragePort::new(pool.clone(), &s3_settings).await?);
            let backend: Arc<dyn StorageReconcileBackend> =
                S3ReconcileBackend::new(&s3_settings).await? as Arc<dyn StorageReconcileBackend>;
            (
                port.clone() as Arc<dyn StorageResolverPort>,
                port as Arc<dyn StorageProjectionPort>,
                backend,
                true,
            )
        }
    };
    Ok(ports)
}

pub fn build_storage_projection_queue(pool: &PgPool) -> Arc<PgStorageProjectionQueue> {
    Arc::new(PgStorageProjectionQueue::new(pool.clone()))
}

#[cfg(test)]
mod tests {
    use crate::config::StorageBackend;

    #[test]
    fn storage_backend_parse() {
        assert_eq!(
            "fs".parse::<StorageBackend>().unwrap(),
            StorageBackend::Filesystem
        );
        assert!("s3".parse::<StorageBackend>().is_ok());
    }
}
