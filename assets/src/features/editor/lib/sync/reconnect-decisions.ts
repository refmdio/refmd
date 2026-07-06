export function shouldUseDeltaReconnect(params: {
  stateKnownSnapshotId: string | null;
  pinSnapshotId: string | null;
  hasLastSavedState: boolean;
  forceCompleteReconnect: boolean;
}): boolean {
  return (
    params.stateKnownSnapshotId !== null &&
    params.hasLastSavedState &&
    !params.forceCompleteReconnect &&
    (!params.pinSnapshotId || params.pinSnapshotId === params.stateKnownSnapshotId)
  );
}

export function shouldRecomputeUnsavedLocalUpdate(hasSavedPendingUpdate: boolean): boolean {
  return !hasSavedPendingUpdate;
}

export function shouldFailNoBaselineLocalTextReconnect(
  currentText: string,
  localText: string,
): boolean {
  return currentText !== localText;
}
