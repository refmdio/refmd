import {
  buildDocumentStatePinKey,
  getDocumentStatePin,
  putDocumentStatePin,
  updatePinFromState,
  type DocumentStatePin,
} from "@/shared/lib/anti-rollback/document-state-pins";
import { collectClockObservations } from "@/shared/lib/anti-rollback/clock-observations";
import type { DocumentPayload } from "@/shared/lib/ws/document-payloads";
import type { DocumentState } from "../../model/document-state/types";
import { createRollbackAttackError } from "./inbound-verify-decrypt";

function getIncomingVersion(payload: DocumentPayload): number {
  let incomingVersion = payload.latestVersion ?? 0;

  for (const update of payload.updates) {
    if (update.version > incomingVersion) {
      incomingVersion = update.version;
    }
  }

  return incomingVersion;
}

function collectRollbackWarnings(
  payload: DocumentPayload,
  state: DocumentState,
  pin: DocumentStatePin,
): string[] {
  const rollbackWarnings: string[] = [];
  const incomingVersion = getIncomingVersion(payload);

  if (incomingVersion > 0 && incomingVersion < pin.latestGlobalVersion) {
    rollbackWarnings.push(
      `Version rollback: server=${incomingVersion} < pin=${pin.latestGlobalVersion}`,
    );
  }

  const sameSnapshot = payload.snapshot
    ? payload.snapshot.publicData.snapshotId === pin.latestSnapshotId
    : true;
  if (!sameSnapshot || payload.updates.length === 0) {
    return rollbackWarnings;
  }

  if (state._lastJoinMode === "complete") {
    const clockObservations = collectClockObservations(payload.updates);
    for (const [deviceKey, pinnedClock] of Object.entries(pin.perDeviceMaxClocks)) {
      const warning = summarizeClockWarning(deviceKey, pinnedClock, clockObservations);
      if (warning) rollbackWarnings.push(warning);
    }

    return rollbackWarnings;
  }

  const clockObservations = collectClockObservations(payload.updates);
  for (const [deviceKey, pinnedClock] of Object.entries(pin.perDeviceMaxClocks)) {
    const warning = summarizeClockWarning(deviceKey, pinnedClock, clockObservations);
    if (warning) rollbackWarnings.push(warning);
  }

  return rollbackWarnings;
}

function summarizeClockWarning(
  deviceKey: string,
  pinnedClock: number,
  clockObservations: Map<string, { max: number; seen: Set<number> }>,
): string | null {
  const observed = clockObservations.get(deviceKey);
  if (!observed) return null;
  if (observed.max < pinnedClock) {
    return `Clock rollback: device=${deviceKey} clock=${observed.max} < pin=${pinnedClock}`;
  }

  let expected = pinnedClock + 1;
  for (const clock of [...observed.seen].sort((a, b) => a - b)) {
    if (clock <= pinnedClock) continue;
    if (clock > expected) {
      return `Clock gap: device=${deviceKey} expected=${expected} got=${clock}`;
    }
    expected = clock + 1;
  }
  return null;
}

export async function detectDocumentRollback(
  payload: DocumentPayload,
  state: DocumentState,
  documentId: string,
): Promise<DocumentStatePin | null> {
  const pinKey =
    state.access.kind === "share"
      ? buildDocumentStatePinKey(documentId, state.access.shareId)
      : buildDocumentStatePinKey(documentId);
  const pin = await getDocumentStatePin(pinKey).catch(() => null);
  if (!pin) return null;

  const rollbackWarnings = collectRollbackWarnings(payload, state, pin);
  if (rollbackWarnings.length === 0) {
    return pin;
  }

  throw createRollbackAttackError(rollbackWarnings.join("; "));
}

export function persistDocumentRollbackPin(documentId: string, state: DocumentState): void {
  const pinKey =
    state.access.kind === "share"
      ? buildDocumentStatePinKey(documentId, state.access.shareId)
      : buildDocumentStatePinKey(documentId);

  getDocumentStatePin(pinKey).then((existing) => {
    const pin = updatePinFromState(
      existing,
      pinKey,
      state.activeSnapshotId,
      state.snapshotProofHash,
      state.snapshotCiphertextHash,
      state.confirmedClocks,
      state.latestVersion,
      documentId,
    );
    putDocumentStatePin(pin).catch(() => {});
  });
}
