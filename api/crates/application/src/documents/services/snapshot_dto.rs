use crate::documents::dtos::{SnapshotDiffDto, SnapshotDiffSideDto, SnapshotSummaryDto};
use crate::documents::use_cases::snapshot_diff::{SnapshotDiffResult, SnapshotDiffSide};

pub(super) fn snapshot_diff_dto_from_result(result: SnapshotDiffResult) -> SnapshotDiffDto {
    SnapshotDiffDto {
        base: snapshot_diff_side_from_use_case(result.base),
        target: snapshot_diff_side_from_use_case(result.target),
        diff: result.diff,
    }
}

fn snapshot_diff_side_from_use_case(side: SnapshotDiffSide) -> SnapshotDiffSideDto {
    match side {
        SnapshotDiffSide::Current { markdown } => SnapshotDiffSideDto::Current { markdown },
        SnapshotDiffSide::Snapshot { record, markdown } => SnapshotDiffSideDto::Snapshot {
            snapshot: SnapshotSummaryDto::from(record),
            markdown,
        },
    }
}

