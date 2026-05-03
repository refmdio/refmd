import { openIdb, idbConditionalPut, idbGet, idbPut } from "@/shared/lib/storage/idb";

const DB_NAME = "refmd-security";
const DB_VERSION = 1;
const STORE_NAME = "document-state-pins";

export interface DocumentStatePin {
  documentId: string;
  targetDocumentId: string;
  latestSnapshotId: string | null;
  latestSnapshotProofHash: string;
  latestSnapshotCiphertextHash: string;
  perDeviceMaxClocks: Record<string, number>;
  latestGlobalVersion: number;
  observedAt: number;
}

interface PutDocumentStatePinOptions {
  expectedPreviousSnapshotId?: string | null;
  allowSnapshotChangeAtSameVersion?: boolean;
}

export function hasCompleteSnapshotPin(
  pin: DocumentStatePin | null | undefined,
): pin is DocumentStatePin & { latestSnapshotId: string } {
  return (
    !!pin?.latestSnapshotId && !!pin.latestSnapshotProofHash && !!pin.latestSnapshotCiphertextHash
  );
}

export function buildDocumentStatePinKey(documentId: string, shareId?: string): string {
  if (!shareId) {
    return documentId;
  }

  return `share:${shareId}:${documentId}`;
}

function openSecurityDb(): Promise<IDBDatabase> {
  return openIdb(DB_NAME, DB_VERSION, (db, oldVersion) => {
    if (oldVersion < 1) {
      db.createObjectStore(STORE_NAME, { keyPath: "documentId" });
    }
  });
}

export async function getDocumentStatePin(documentId: string): Promise<DocumentStatePin | null> {
  const db = await openSecurityDb();
  const pin = await idbGet<DocumentStatePin>(db, STORE_NAME, documentId);
  return pin ?? null;
}

export async function putDocumentStatePin(
  pin: DocumentStatePin,
  options: PutDocumentStatePinOptions = {},
): Promise<void> {
  const db = await openSecurityDb();
  await idbConditionalPut<DocumentStatePin>(db, STORE_NAME, pin.documentId, pin, (existing) => {
    if (!existing) return true;
    if (pin.latestGlobalVersion < existing.latestGlobalVersion) return false;
    if (pin.observedAt < existing.observedAt) return false;
    const snapshotChanged =
      existing.latestSnapshotId !== pin.latestSnapshotId ||
      existing.latestSnapshotProofHash !== pin.latestSnapshotProofHash ||
      existing.latestSnapshotCiphertextHash !== pin.latestSnapshotCiphertextHash;
    if (snapshotChanged) {
      if (
        "expectedPreviousSnapshotId" in options &&
        existing.latestSnapshotId !== options.expectedPreviousSnapshotId
      ) {
        return false;
      }
      if (
        pin.latestGlobalVersion === existing.latestGlobalVersion &&
        !options.allowSnapshotChangeAtSameVersion
      ) {
        return false;
      }
      return true;
    }
    return clocksMonotonicallyAdvanced(existing.perDeviceMaxClocks, pin.perDeviceMaxClocks);
  });
}

export async function replaceDocumentStatePin(pin: DocumentStatePin): Promise<void> {
  const db = await openSecurityDb();
  await idbPut(db, STORE_NAME, pin);
}

function clocksMonotonicallyAdvanced(
  existing: Record<string, number>,
  incoming: Record<string, number>,
): boolean {
  for (const [deviceKey, existingClock] of Object.entries(existing)) {
    const incomingClock = incoming[deviceKey] ?? -1;
    if (incomingClock < existingClock) {
      return false;
    }
  }
  return true;
}

export function mergeClockMax(
  ...clockSets: Array<Record<string, number> | null | undefined>
): Record<string, number> {
  const merged: Record<string, number> = {};
  for (const clocks of clockSets) {
    if (!clocks) continue;
    for (const [key, clock] of Object.entries(clocks)) {
      if (clock > (merged[key] ?? -1)) {
        merged[key] = clock;
      }
    }
  }
  return merged;
}

export function updatePinFromState(
  existing: DocumentStatePin | null,
  documentId: string,
  snapshotId: string | null,
  snapshotProofHash: string,
  snapshotCiphertextHash: string,
  clocks: Record<string, number>,
  version: number,
  targetDocumentId = documentId,
): DocumentStatePin {
  const pin: DocumentStatePin = existing ?? {
    documentId,
    targetDocumentId,
    latestSnapshotId: null,
    latestSnapshotProofHash: "",
    latestSnapshotCiphertextHash: "",
    perDeviceMaxClocks: {},
    latestGlobalVersion: 0,
    observedAt: 0,
  };

  pin.targetDocumentId = targetDocumentId;

  const hasCompleteSnapshotBaseline =
    !!snapshotId && !!snapshotProofHash && !!snapshotCiphertextHash;
  const snapshotChanged = hasCompleteSnapshotBaseline && snapshotId !== pin.latestSnapshotId;
  if (hasCompleteSnapshotBaseline) {
    pin.latestSnapshotId = snapshotId;
    pin.latestSnapshotProofHash = snapshotProofHash;
    pin.latestSnapshotCiphertextHash = snapshotCiphertextHash;
  }
  if (snapshotChanged) {
    // Clocks reset on snapshot transition
    pin.perDeviceMaxClocks = { ...clocks };
  } else if (!snapshotId || snapshotId === pin.latestSnapshotId) {
    for (const [key, clock] of Object.entries(clocks)) {
      if (clock > (pin.perDeviceMaxClocks[key] ?? -1)) {
        pin.perDeviceMaxClocks[key] = clock;
      }
    }
  }
  if (version > pin.latestGlobalVersion) {
    pin.latestGlobalVersion = version;
  }
  pin.observedAt = Date.now();
  return pin;
}
