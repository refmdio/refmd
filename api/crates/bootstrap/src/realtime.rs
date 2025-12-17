use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tracing::info;


use application::documents::ports::document_snapshot_archive_repository::DocumentSnapshotArchiveRepository;
use application::documents::ports::linkgraph_repository::LinkGraphRepository;
use application::documents::ports::realtime::realtime_port::RealtimeEngine;
use application::core::ports::storage::storage_port::StorageResolverPort;
use application::core::ports::storage::storage_projection_queue::StorageProjectionQueue;
use application::documents::services::realtime::doc_hydration::DocHydrationService;
use application::documents::services::realtime::snapshot::SnapshotService;
use crate::config::Config;
use infrastructure::core::db::PgPool;

pub struct RealtimeStack {
    pub engine: Arc<dyn RealtimeEngine>,
    pub snapshot_service: Arc<SnapshotService>,
    pub local_hub: Option<infrastructure::documents::realtime::Hub>,
}

#[allow(clippy::too_many_arguments)]
pub async fn build_realtime_stack(
    cfg: &Config,
    pool: &PgPool,
    storage_resolver: Arc<dyn StorageResolverPort>,
    storage_job_queue: Arc<dyn StorageProjectionQueue>,
    snapshot_archive_repo: Arc<dyn DocumentSnapshotArchiveRepository>,
) -> anyhow::Result<RealtimeStack> {
    let auto_archive_interval = Duration::from_secs(cfg.snapshot_archive_interval_secs);

    if cfg.cluster_mode {
        info!("cluster_mode_enabled");
        let redis_settings = infrastructure::documents::realtime::RedisRealtimeConfig {
            redis_url: cfg
                .redis_url
                .clone()
                .context("REDIS_URL must be set when CLUSTER_MODE=1")?,
            stream_prefix: cfg.redis_stream_prefix.clone(),
            stream_max_len: cfg.redis_stream_max_len,
            task_debounce_ms: cfg.redis_task_debounce_ms,
            min_message_lifetime_ms: cfg.redis_min_message_lifetime_ms,
            awareness_ttl_ms: cfg.redis_awareness_ttl_ms,
            snapshot_archive_interval_secs: cfg.snapshot_archive_interval_secs,
            spawn_persistence_worker: true,
        };
        let engine = Arc::new(
            infrastructure::documents::realtime::RedisRealtimeEngine::from_config(
                redis_settings,
                pool.clone(),
                storage_resolver.clone(),
                storage_job_queue.clone(),
            )?,
        );
        let snapshot_service = engine.snapshot_service();
        let engine_trait: Arc<dyn RealtimeEngine> = engine.clone();
        return Ok(RealtimeStack {
            engine: engine_trait,
            snapshot_service,
            local_hub: None,
        });
    }

    info!("cluster_mode_disabled_using_local_hub");
    let doc_state_reader: Arc<
        dyn application::documents::ports::realtime::realtime_hydration_port::DocStateReader,
    > = Arc::new(infrastructure::documents::realtime::SqlxDocStateReader::new(
        pool.clone(),
    ));
    let backlog_reader: Arc<
        dyn application::documents::ports::realtime::realtime_hydration_port::RealtimeBacklogReader,
    > = Arc::new(infrastructure::documents::realtime::NoopBacklogReader::default());
    let doc_persistence: Arc<
        dyn application::documents::ports::realtime::realtime_persistence_port::DocPersistencePort,
    > = Arc::new(infrastructure::documents::realtime::SqlxDocPersistenceAdapter::new(
        pool.clone(),
    ));
    let linkgraph_repo: Arc<dyn LinkGraphRepository> = Arc::new(
        infrastructure::documents::db::repositories::linkgraph_repository_sqlx::SqlxLinkGraphRepository::new(
            pool.clone(),
        ),
    );
    let tagging_repo: Arc<dyn application::documents::ports::tagging::tagging_repository::TaggingRepository> =
        Arc::new(
            infrastructure::documents::db::repositories::tagging_repository_sqlx::SqlxTaggingRepository::new(
                pool.clone(),
            ),
        );
    let hydration_service = Arc::new(DocHydrationService::new(
        doc_state_reader.clone(),
        backlog_reader,
        storage_resolver.clone(),
    ));
    let snapshot_service = Arc::new(SnapshotService::new(
        doc_state_reader.clone(),
        doc_persistence.clone(),
        linkgraph_repo,
        tagging_repo,
        snapshot_archive_repo.clone(),
        storage_job_queue.clone(),
    ));
    let hub = infrastructure::documents::realtime::Hub::new(
        hydration_service,
        snapshot_service.clone(),
        doc_persistence,
        auto_archive_interval,
    );
    let engine = Arc::new(infrastructure::documents::realtime::LocalRealtimeEngine { hub: hub.clone() });
    let engine_trait: Arc<dyn RealtimeEngine> = engine.clone();
    Ok(RealtimeStack {
        engine: engine_trait,
        snapshot_service,
        local_hub: Some(hub),
    })
}
