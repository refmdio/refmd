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

function collectPayloadClockObservations(
  payload: DocumentPayload,
  baselineClocks: Record<string, number> = {},
): Map<string, { max: number; seen: Set<number> }> {
  const observations = new Map<string, { max: number; seen: Set<number> }>();
  for (const [deviceKey, clock] of Object.entries(baselineClocks)) {
    observations.set(deviceKey, { max: clock, seen: new Set() });
  }

  for (const [deviceKey, observed] of collectClockObservations(payload.updates)) {
    const existing = observations.get(deviceKey);
    if (existing) {
      existing.max = Math.max(existing.max, observed.max);
      for (const clock of observed.seen) {
        existing.seen.add(clock);
      }
      continue;
    }
    observations.set(deviceKey, observed);
  }

  const snapshotClocks = payload.snapshot?.publicData.parentSnapshotUpdateClocks ?? {};
  for (const [deviceKey, clock] of Object.entries(snapshotClocks)) {
    const existing = observations.get(deviceKey);
    if (existing) {
      existing.max = Math.max(existing.max, clock);
      continue;
    }
    observations.set(deviceKey, { max: clock, seen: new Set() });
  }
  return observations;
}

export function collectRollbackWarnings(
  payload: DocumentPayload,
  pin: DocumentStatePin,
  baselineClocks: Record<string, number> = {},
): string[] {
  const rollbackWarnings: string[] = [];
  const incomingVersion = getIncomingVersion(payload);

  if (incomingVersion > 0 && incomingVersion < pin.latestGlobalVersion) {
    rollbackWarnings.push(
      `Version rollback: server=${incomingVersion} < pin=${pin.latestGlobalVersion}`,
    );
  }

  const clockObservations = collectPayloadClockObservations(payload, baselineClocks);
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

  const baselineClocks = payload.snapshot === null ? state.confirmedClocks : undefined;
  const rollbackWarnings = collectRollbackWarnings(payload, pin, baselineClocks);
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
