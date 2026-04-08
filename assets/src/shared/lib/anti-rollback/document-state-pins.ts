import { openIdb, idbConditionalPut, idbGet } from "@/shared/lib/storage/idb";

const DB_NAME = "refmd-security";
const DB_VERSION = 1;
const STORE_NAME = "document-state-pins";

export interface DocumentStatePin {
  documentId: string;
  latestSnapshotId: string | null;
  latestSnapshotProofHash: string;
  latestSnapshotCiphertextHash: string;
  perDeviceMaxClocks: Record<string, number>;
  latestGlobalVersion: number;
  observedAt: number;
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

export async function putDocumentStatePin(pin: DocumentStatePin): Promise<void> {
  const db = await openSecurityDb();
  await idbConditionalPut<DocumentStatePin>(db, STORE_NAME, pin.documentId, pin, (existing) => {
    if (!existing) return true;
    if (existing.latestSnapshotId !== pin.latestSnapshotId) return true;
    return clocksMonotonicallyAdvanced(existing.perDeviceMaxClocks, pin.perDeviceMaxClocks);
  });
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

export function updatePinFromState(
  existing: DocumentStatePin | null,
  documentId: string,
  snapshotId: string | null,
  snapshotProofHash: string,
  snapshotCiphertextHash: string,
  clocks: Record<string, number>,
  version: number,
): DocumentStatePin {
  const pin: DocumentStatePin = existing ?? {
    documentId,
    latestSnapshotId: null,
    latestSnapshotProofHash: "",
    latestSnapshotCiphertextHash: "",
    perDeviceMaxClocks: {},
    latestGlobalVersion: 0,
    observedAt: 0,
  };

  const snapshotChanged = snapshotId && snapshotId !== pin.latestSnapshotId;
  if (snapshotId) {
    pin.latestSnapshotId = snapshotId;
    pin.latestSnapshotProofHash = snapshotProofHash;
    pin.latestSnapshotCiphertextHash = snapshotCiphertextHash;
  }
  if (snapshotChanged) {
    // Clocks reset on snapshot transition
    pin.perDeviceMaxClocks = { ...clocks };
  } else {
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
