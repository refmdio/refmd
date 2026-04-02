import { idbGet, idbPut, toArrayBuffer } from "@/shared/lib/idb";
import { openOfflineDb, STORE_PENDING_CHANGES } from "./offline-store-db";
export type PendingSyncBlockReason = "not_a_member" | "permission_denied";
export interface PendingChangesEntry {
  documentId: string;
  encryptedDiff: Uint8Array;
  diffNonce: Uint8Array;
  keyVersion: number;
  createdAt: number;
  updatedAt: number;
  syncBlockedReason?: PendingSyncBlockReason | null;
  syncBlockedAt?: number | null;
}
interface PendingChangesIdb {
  documentId: string;
  encryptedDiff: ArrayBuffer;
  diffNonce: ArrayBuffer;
  keyVersion: number;
  createdAt: number;
  updatedAt: number;
  syncBlockedReason?: PendingSyncBlockReason;
  syncBlockedAt?: number;
}
function serializePendingChanges(entry: PendingChangesEntry): PendingChangesIdb {
  return {
    documentId: entry.documentId,
    encryptedDiff: toArrayBuffer(entry.encryptedDiff),
    diffNonce: toArrayBuffer(entry.diffNonce),
    keyVersion: entry.keyVersion,
    createdAt: entry.createdAt,
    updatedAt: entry.updatedAt,
    syncBlockedReason: entry.syncBlockedReason ?? undefined,
    syncBlockedAt: entry.syncBlockedAt ?? undefined,
  };
}
function deserializePendingChanges(raw: PendingChangesIdb): PendingChangesEntry {
  return {
    documentId: raw.documentId,
    encryptedDiff: new Uint8Array(raw.encryptedDiff),
    diffNonce: new Uint8Array(raw.diffNonce),
    keyVersion: raw.keyVersion,
    createdAt: raw.createdAt,
    updatedAt: raw.updatedAt,
    syncBlockedReason: raw.syncBlockedReason ?? null,
    syncBlockedAt: raw.syncBlockedAt ?? null,
  };
}
export async function getPendingChanges(documentId: string): Promise<PendingChangesEntry | null> {
  const db = await openOfflineDb();
  const raw = await idbGet<PendingChangesIdb>(db, STORE_PENDING_CHANGES, documentId);
  return raw ? deserializePendingChanges(raw) : null;
}
export async function putPendingChanges(entry: PendingChangesEntry): Promise<void> {
  const db = await openOfflineDb();
  await idbPut(db, STORE_PENDING_CHANGES, serializePendingChanges(entry));
}
export async function blockPendingChangesSync(
  documentId: string,
  reason: PendingSyncBlockReason,
): Promise<void> {
  const existing = await getPendingChanges(documentId);
  if (!existing) return;
  await putPendingChanges({
    ...existing,
    syncBlockedReason: reason,
    syncBlockedAt: Date.now(),
  });
}
export async function deletePendingChanges(documentId: string): Promise<void> {
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_PENDING_CHANGES, "readwrite");
    tx.objectStore(STORE_PENDING_CHANGES).delete(documentId);
    tx.oncomplete = () => {
      resolve();
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}
export async function getAllPendingChanges(): Promise<PendingChangesEntry[]> {
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_PENDING_CHANGES, "readonly");
    const req = tx.objectStore(STORE_PENDING_CHANGES).getAll();
    req.onerror = () => reject(req.error);
    tx.oncomplete = () => {
      resolve((req.result as PendingChangesIdb[]).map(deserializePendingChanges));
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}
