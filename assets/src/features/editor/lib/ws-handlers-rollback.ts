import {
  getDocumentStatePin,
  putDocumentStatePin,
  updatePinFromState,
  type DocumentStatePin,
} from "@/shared/lib/anti-rollback/document-state-pins";
import { collectClockObservations } from "@/shared/lib/anti-rollback/clock-observations";
import type { DocumentPayload } from "@/shared/lib/ws/document-payloads";
import type { DocumentState } from "./document-state-cache";
import { createRollbackAttackError } from "./ws-verify-decrypt";

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
      const observed = clockObservations.get(deviceKey);
      if (!observed) continue;

      if (observed.max < pinnedClock) {
        rollbackWarnings.push(
          `Clock rollback: device=${deviceKey} clock=${observed.max} < pin=${pinnedClock}`,
        );
      } else if (observed.max > pinnedClock + 1 && !observed.seen.has(pinnedClock + 1)) {
        rollbackWarnings.push(
          `Clock gap: device=${deviceKey} expected=${pinnedClock + 1} got=${observed.max}`,
        );
      }
    }

    return rollbackWarnings;
  }

  for (const update of payload.updates) {
    const pinnedClock = pin.perDeviceMaxClocks[update.publicData.signingPubKey];
    if (pinnedClock === undefined) continue;

    if (update.publicData.clock < pinnedClock) {
      rollbackWarnings.push(
        `Clock rollback: device=${update.publicData.signingPubKey} clock=${update.publicData.clock} < pin=${pinnedClock}`,
      );
    } else if (update.publicData.clock > pinnedClock + 1) {
      rollbackWarnings.push(
        `Clock gap: device=${update.publicData.signingPubKey} expected=${pinnedClock + 1} got=${update.publicData.clock}`,
      );
    }
  }

  return rollbackWarnings;
}

export async function detectDocumentRollback(
  payload: DocumentPayload,
  state: DocumentState,
  documentId: string,
): Promise<DocumentStatePin | null> {
  const pin = await getDocumentStatePin(documentId).catch(() => null);
  if (!pin) return null;

  const rollbackWarnings = collectRollbackWarnings(payload, state, pin);
  if (rollbackWarnings.length === 0) {
    return pin;
  }

  if (state._headlessSync) {
    throw createRollbackAttackError("rollback_approval_required");
  }

  const { requestRollbackApproval } = await import("./document-state-cache");
  await requestRollbackApproval(documentId, rollbackWarnings.join("; "));

  // User approved: reset in-memory version to avoid subsequent regression check failure.
  state.latestVersion = 0;
  return pin;
}

export function persistDocumentRollbackPin(documentId: string, state: DocumentState): void {
  getDocumentStatePin(documentId).then((existing) => {
    const pin = updatePinFromState(
      existing,
      documentId,
      state.activeSnapshotId,
      state.snapshotProofHash,
      state.snapshotCiphertextHash,
      state.confirmedClocks,
      state.latestVersion,
    );
    putDocumentStatePin(pin).catch(() => {});
  });
}
