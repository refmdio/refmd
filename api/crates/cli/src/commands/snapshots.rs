use std::time::Duration;

use anyhow::Result;
use sqlx::Row;
use tokio::time::sleep;
use uuid::Uuid;

use bootstrap::infrastructure::core::db::PgPool;

use crate::cli::{SnapshotArchiveKindArg, SnapshotCommand, SnapshotPruneTarget};
use crate::deps::Deps;

pub(crate) async fn handle(deps: &Deps, cmd: SnapshotCommand) -> Result<()> {
    match cmd {
        SnapshotCommand::Stats {
            snapshots_keep,
            archives_keep,
            archive_kind,
            target,
        } => {
            let snapshots_keep = snapshots_keep.unwrap_or(deps.snapshot_keep_versions);
            let archives_keep = archives_keep.unwrap_or(deps.snapshot_archive_keep_versions);
            print_stats(
                &deps.pool,
                target,
                snapshots_keep,
                archives_keep,
                archive_kind,
            )
            .await
        }
        SnapshotCommand::Prune {
            snapshots_keep,
            archives_keep,
            archive_kind,
            target,
            document_batch_size,
            delete_batch_size,
            max_docs,
            sleep_ms,
            dry_run,
        } => {
            let snapshots_keep = snapshots_keep.unwrap_or(deps.snapshot_keep_versions);
            let archives_keep = archives_keep.unwrap_or(deps.snapshot_archive_keep_versions);
            prune(PruneOptions {
                pool: &deps.pool,
                target,
                snapshots_keep,
                archives_keep,
                archive_kind,
                document_batch_size,
                delete_batch_size,
                max_docs,
                sleep_ms,
                dry_run,
            })
            .await
        }
    }
}

struct PruneOptions<'a> {
    pool: &'a PgPool,
    target: SnapshotPruneTarget,
    snapshots_keep: i64,
    archives_keep: i64,
    archive_kind: SnapshotArchiveKindArg,
    document_batch_size: i64,
    delete_batch_size: i64,
    max_docs: Option<i64>,
    sleep_ms: u64,
    dry_run: bool,
}

#[derive(Debug)]
struct RetentionStats {
    docs: i64,
    rows: i64,
    target_rows: i64,
    excess_rows: i64,
    docs_over_keep: i64,
    max_rows_per_doc: i64,
}

#[derive(Debug)]
struct OverLimitDoc {
    document_id: Uuid,
    rows: i64,
}

#[derive(Debug, Default)]
struct PruneReport {
    docs_processed: i64,
    rows_deleted: u64,
}

async fn print_stats(
    pool: &PgPool,
    target: SnapshotPruneTarget,
    snapshots_keep: i64,
    archives_keep: i64,
    archive_kind: SnapshotArchiveKindArg,
) -> Result<()> {
    if includes_snapshots(target) {
        let stats = snapshot_stats(pool, snapshots_keep).await?;
        print_retention_stats("document_snapshots", snapshots_keep, None, &stats);
    }

    if includes_archives(target) {
        let stats = archive_stats(pool, archive_kind.as_str(), archives_keep).await?;
        print_retention_stats(
            "document_snapshot_archives",
            archives_keep,
            Some(archive_kind.as_str()),
            &stats,
        );
    }

    Ok(())
}

async fn prune(options: PruneOptions<'_>) -> Result<()> {
    print_stats(
        options.pool,
        options.target,
        options.snapshots_keep,
        options.archives_keep,
        options.archive_kind,
    )
    .await?;

    if options.dry_run {
        println!("snapshot_prune.dry_run=true");
        return Ok(());
    }

    if includes_snapshots(options.target) {
        let report = prune_snapshots(&options).await?;
        println!(
            "document_snapshots.pruned_docs={} document_snapshots.deleted_rows={}",
            report.docs_processed, report.rows_deleted
        );
    }

    if includes_archives(options.target) {
        let report = prune_archives(&options).await?;
        println!(
            "document_snapshot_archives.kind={} document_snapshot_archives.pruned_docs={} document_snapshot_archives.deleted_rows={}",
            options.archive_kind.as_str(),
            report.docs_processed,
            report.rows_deleted
        );
    }

    print_stats(
        options.pool,
        options.target,
        options.snapshots_keep,
        options.archives_keep,
        options.archive_kind,
    )
    .await?;

    Ok(())
}

async fn prune_snapshots(options: &PruneOptions<'_>) -> Result<PruneReport> {
    let mut report = PruneReport::default();

    loop {
        if reached_max_docs(report.docs_processed, options.max_docs) {
            break;
        }

        let docs = over_limit_snapshot_docs(
            options.pool,
            options.snapshots_keep,
            remaining_doc_limit(
                options.document_batch_size,
                report.docs_processed,
                options.max_docs,
            ),
        )
        .await?;
        if docs.is_empty() {
            break;
        }

        for doc in docs {
            if reached_max_docs(report.docs_processed, options.max_docs) {
                break;
            }
            let deleted = prune_snapshot_doc(
                options.pool,
                doc.document_id,
                options.snapshots_keep,
                options.delete_batch_size,
                options.sleep_ms,
            )
            .await?;
            report.docs_processed += 1;
            report.rows_deleted += deleted;
            println!(
                "document_snapshots.document_id={} document_snapshots.before_rows={} document_snapshots.deleted_rows={}",
                doc.document_id, doc.rows, deleted
            );
        }
    }

    Ok(report)
}

async fn prune_archives(options: &PruneOptions<'_>) -> Result<PruneReport> {
    let mut report = PruneReport::default();

    loop {
        if reached_max_docs(report.docs_processed, options.max_docs) {
            break;
        }

        let docs = over_limit_archive_docs(
            options.pool,
            options.archive_kind.as_str(),
            options.archives_keep,
            remaining_doc_limit(
                options.document_batch_size,
                report.docs_processed,
                options.max_docs,
            ),
        )
        .await?;
        if docs.is_empty() {
            break;
        }

        for doc in docs {
            if reached_max_docs(report.docs_processed, options.max_docs) {
                break;
            }
            let deleted = prune_archive_doc(
                options.pool,
                doc.document_id,
                options.archive_kind.as_str(),
                options.archives_keep,
                options.delete_batch_size,
                options.sleep_ms,
            )
            .await?;
            report.docs_processed += 1;
            report.rows_deleted += deleted;
            println!(
                "document_snapshot_archives.kind={} document_snapshot_archives.document_id={} document_snapshot_archives.before_rows={} document_snapshot_archives.deleted_rows={}",
                options.archive_kind.as_str(),
                doc.document_id,
                doc.rows,
                deleted
            );
        }
    }

    Ok(report)
}

async fn prune_snapshot_doc(
    pool: &PgPool,
    document_id: Uuid,
    keep: i64,
    delete_batch_size: i64,
    sleep_ms: u64,
) -> Result<u64> {
    let Some(cutoff_version) = snapshot_cutoff_version(pool, document_id, keep).await? else {
        return Ok(0);
    };
    let mut total_deleted = 0;

    loop {
        let deleted = sqlx::query(
            r#"DELETE FROM document_snapshots
               WHERE id IN (
                   SELECT id
                   FROM document_snapshots
                   WHERE document_id = $1
                     AND version < $2
                   ORDER BY version ASC
                   LIMIT $3
               )"#,
        )
        .bind(document_id)
        .bind(cutoff_version)
        .bind(delete_batch_size)
        .execute(pool)
        .await?
        .rows_affected();

        if deleted == 0 {
            break;
        }
        total_deleted += deleted;
        sleep_between_batches(sleep_ms).await;
    }

    Ok(total_deleted)
}

async fn prune_archive_doc(
    pool: &PgPool,
    document_id: Uuid,
    kind: &str,
    keep: i64,
    delete_batch_size: i64,
    sleep_ms: u64,
) -> Result<u64> {
    let Some(cutoff_version) = archive_cutoff_version(pool, document_id, kind, keep).await? else {
        return Ok(0);
    };
    let mut total_deleted = 0;

    loop {
        let deleted = sqlx::query(
            r#"DELETE FROM document_snapshot_archives
               WHERE id IN (
                   SELECT id
                   FROM document_snapshot_archives
                   WHERE document_id = $1
                     AND kind = $2
                     AND version < $3
                   ORDER BY version ASC
                   LIMIT $4
               )"#,
        )
        .bind(document_id)
        .bind(kind)
        .bind(cutoff_version)
        .bind(delete_batch_size)
        .execute(pool)
        .await?
        .rows_affected();

        if deleted == 0 {
            break;
        }
        total_deleted += deleted;
        sleep_between_batches(sleep_ms).await;
    }

    Ok(total_deleted)
}

async fn snapshot_cutoff_version(
    pool: &PgPool,
    document_id: Uuid,
    keep: i64,
) -> Result<Option<i32>> {
    let row = sqlx::query(
        r#"SELECT MIN(version) AS cutoff_version
           FROM (
               SELECT version
               FROM document_snapshots
               WHERE document_id = $1
               ORDER BY version DESC
               LIMIT $2
           ) kept"#,
    )
    .bind(document_id)
    .bind(keep)
    .fetch_one(pool)
    .await?;

    let cutoff_version: Option<i32> = row.try_get("cutoff_version")?;
    Ok(cutoff_version)
}

async fn archive_cutoff_version(
    pool: &PgPool,
    document_id: Uuid,
    kind: &str,
    keep: i64,
) -> Result<Option<i32>> {
    let row = sqlx::query(
        r#"SELECT MIN(version) AS cutoff_version
           FROM (
               SELECT version
               FROM document_snapshot_archives
               WHERE document_id = $1
                 AND kind = $2
               ORDER BY version DESC
               LIMIT $3
           ) kept"#,
    )
    .bind(document_id)
    .bind(kind)
    .bind(keep)
    .fetch_one(pool)
    .await?;

    let cutoff_version: Option<i32> = row.try_get("cutoff_version")?;
    Ok(cutoff_version)
}

async fn over_limit_snapshot_docs(
    pool: &PgPool,
    keep: i64,
    limit: i64,
) -> Result<Vec<OverLimitDoc>> {
    let rows = sqlx::query(
        r#"SELECT document_id, COUNT(*)::bigint AS rows
           FROM document_snapshots
           GROUP BY document_id
           HAVING COUNT(*) > $1
           ORDER BY COUNT(*) DESC
           LIMIT $2"#,
    )
    .bind(keep)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(row_to_over_limit_doc).collect()
}

async fn over_limit_archive_docs(
    pool: &PgPool,
    kind: &str,
    keep: i64,
    limit: i64,
) -> Result<Vec<OverLimitDoc>> {
    let rows = sqlx::query(
        r#"SELECT document_id, COUNT(*)::bigint AS rows
           FROM document_snapshot_archives
           WHERE kind = $1
           GROUP BY document_id
           HAVING COUNT(*) > $2
           ORDER BY COUNT(*) DESC
           LIMIT $3"#,
    )
    .bind(kind)
    .bind(keep)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(row_to_over_limit_doc).collect()
}

fn row_to_over_limit_doc(row: sqlx::postgres::PgRow) -> Result<OverLimitDoc> {
    Ok(OverLimitDoc {
        document_id: row.try_get("document_id")?,
        rows: row.try_get("rows")?,
    })
}

async fn snapshot_stats(pool: &PgPool, keep: i64) -> Result<RetentionStats> {
    let row = sqlx::query(
        r#"WITH per_doc AS (
               SELECT document_id, COUNT(*)::bigint AS rows
               FROM document_snapshots
               GROUP BY document_id
           )
           SELECT
               COALESCE(COUNT(*), 0)::bigint AS docs,
               COALESCE(SUM(rows), 0)::bigint AS rows,
               COALESCE(SUM(LEAST(rows, $1)), 0)::bigint AS target_rows,
               COALESCE(SUM(GREATEST(rows - $1, 0)), 0)::bigint AS excess_rows,
               COALESCE(COUNT(*) FILTER (WHERE rows > $1), 0)::bigint AS docs_over_keep,
               COALESCE(MAX(rows), 0)::bigint AS max_rows_per_doc
           FROM per_doc"#,
    )
    .bind(keep)
    .fetch_one(pool)
    .await?;

    row_to_retention_stats(row)
}

async fn archive_stats(pool: &PgPool, kind: &str, keep: i64) -> Result<RetentionStats> {
    let row = sqlx::query(
        r#"WITH per_doc AS (
               SELECT document_id, COUNT(*)::bigint AS rows
               FROM document_snapshot_archives
               WHERE kind = $1
               GROUP BY document_id
           )
           SELECT
               COALESCE(COUNT(*), 0)::bigint AS docs,
               COALESCE(SUM(rows), 0)::bigint AS rows,
               COALESCE(SUM(LEAST(rows, $2)), 0)::bigint AS target_rows,
               COALESCE(SUM(GREATEST(rows - $2, 0)), 0)::bigint AS excess_rows,
               COALESCE(COUNT(*) FILTER (WHERE rows > $2), 0)::bigint AS docs_over_keep,
               COALESCE(MAX(rows), 0)::bigint AS max_rows_per_doc
           FROM per_doc"#,
    )
    .bind(kind)
    .bind(keep)
    .fetch_one(pool)
    .await?;

    row_to_retention_stats(row)
}

fn row_to_retention_stats(row: sqlx::postgres::PgRow) -> Result<RetentionStats> {
    Ok(RetentionStats {
        docs: row.try_get("docs")?,
        rows: row.try_get("rows")?,
        target_rows: row.try_get("target_rows")?,
        excess_rows: row.try_get("excess_rows")?,
        docs_over_keep: row.try_get("docs_over_keep")?,
        max_rows_per_doc: row.try_get("max_rows_per_doc")?,
    })
}

fn print_retention_stats(table: &str, keep: i64, kind: Option<&str>, stats: &RetentionStats) {
    if let Some(kind) = kind {
        println!("{table}.kind={kind}");
    }
    println!("{table}.keep={keep}");
    println!("{table}.docs={}", stats.docs);
    println!("{table}.rows={}", stats.rows);
    println!("{table}.target_rows={}", stats.target_rows);
    println!("{table}.excess_rows={}", stats.excess_rows);
    println!("{table}.docs_over_keep={}", stats.docs_over_keep);
    println!("{table}.max_rows_per_doc={}", stats.max_rows_per_doc);
}

fn includes_snapshots(target: SnapshotPruneTarget) -> bool {
    matches!(
        target,
        SnapshotPruneTarget::Snapshots | SnapshotPruneTarget::Both
    )
}

fn includes_archives(target: SnapshotPruneTarget) -> bool {
    matches!(
        target,
        SnapshotPruneTarget::Archives | SnapshotPruneTarget::Both
    )
}

fn reached_max_docs(processed: i64, max_docs: Option<i64>) -> bool {
    max_docs.is_some_and(|max| processed >= max)
}

fn remaining_doc_limit(batch_size: i64, processed: i64, max_docs: Option<i64>) -> i64 {
    match max_docs {
        Some(max) => batch_size.min(max - processed).max(1),
        None => batch_size,
    }
}

async fn sleep_between_batches(sleep_ms: u64) {
    if sleep_ms > 0 {
        sleep(Duration::from_millis(sleep_ms)).await;
    }
}
