use uuid::Uuid;

use crate::core::services::access::{self, Actor};
use crate::core::services::errors::ServiceError;
use crate::documents::dtos::{
    SnapshotDetailDto, SnapshotDiffBaseMode, SnapshotDiffDto, SnapshotSummaryDto,
};
use crate::documents::use_cases::list_snapshots::ListSnapshots;
use crate::documents::use_cases::restore_snapshot::RestoreSnapshot;
use crate::documents::use_cases::snapshot_diff::SnapshotDiff;

use super::DocumentService;
use super::snapshot_dto::snapshot_diff_dto_from_result;

impl DocumentService {
    pub async fn list_snapshots(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SnapshotSummaryDto>, ServiceError> {
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|err| match err {
            ServiceError::Forbidden => ServiceError::Unauthorized,
            other => other,
        })?;

        let uc = ListSnapshots {
            snapshots: self.snapshot_service.as_ref(),
        };
        let records = uc
            .execute(doc_id, limit, offset)
            .await
            .map_err(ServiceError::from)?;
        Ok(records.into_iter().map(SnapshotSummaryDto::from).collect())
    }

    pub async fn snapshot_diff(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        snapshot_id: Uuid,
        compare: Option<Uuid>,
        base_mode: SnapshotDiffBaseMode,
    ) -> Result<SnapshotDiffDto, ServiceError> {
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|err| match err {
            ServiceError::Forbidden => ServiceError::Unauthorized,
            other => other,
        })?;

        let uc = SnapshotDiff {
            snapshots: self.snapshot_service.as_ref(),
            realtime: self.realtime.as_ref(),
        };
        let result = uc
            .execute(doc_id, snapshot_id, compare, base_mode)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;

        Ok(snapshot_diff_dto_from_result(result))
    }

    pub async fn restore_snapshot(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        snapshot_id: Uuid,
    ) -> Result<SnapshotSummaryDto, ServiceError> {
        access::require_edit(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|err| match err {
            ServiceError::Forbidden => ServiceError::Unauthorized,
            other => other,
        })?;

        let created_by = match actor {
            Actor::User(uid) => Some(*uid),
            _ => None,
        };

        let uc = RestoreSnapshot {
            snapshots: self.snapshot_service.as_ref(),
            realtime: self.realtime.as_ref(),
        };
        let record = uc
            .execute(doc_id, snapshot_id, created_by)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;

        Ok(SnapshotSummaryDto::from(record))
    }

    /// Get a single snapshot with its encrypted content (E2EE format)
    pub async fn get_snapshot(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        snapshot_id: Uuid,
    ) -> Result<SnapshotDetailDto, ServiceError> {
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|err| match err {
            ServiceError::Forbidden => ServiceError::Unauthorized,
            other => other,
        })?;

        let entry = self
            .snapshot_service
            .get_snapshot_entry(snapshot_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;

        // Verify the snapshot belongs to the requested document
        if entry.record.document_id != doc_id {
            return Err(ServiceError::NotFound);
        }

        Ok(SnapshotDetailDto {
            id: entry.record.id,
            content: entry.bytes,
            nonce: entry.record.nonce,
            created_at: entry.record.created_at,
        })
    }
}
