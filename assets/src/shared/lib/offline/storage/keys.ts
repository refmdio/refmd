import { idbGet, idbPut } from "@/shared/lib/storage/idb";
import { openOfflineDb, STORE_OFFLINE_DEK, STORE_OFFLINE_KEK } from "./db";
interface OfflineDekEntry {
  documentId: string;
  wrappedDek: ArrayBuffer;
  wrappedDekNonce: ArrayBuffer;
  keyVersion: number;
  cachedAt: number;
}
interface OfflineKekEntry {
  workspaceId: string;
  wrappedKek: ArrayBuffer;
  wrappedKekNonce: ArrayBuffer;
  keyVersion: number;
  cachedAt: number;
}
export async function getOfflineDek(documentId: string): Promise<OfflineDekEntry | null> {
  const db = await openOfflineDb();
  const raw = await idbGet<OfflineDekEntry>(db, STORE_OFFLINE_DEK, documentId);
  return raw ?? null;
}
export async function putOfflineDek(entry: OfflineDekEntry): Promise<void> {
  const db = await openOfflineDb();
  await idbPut(db, STORE_OFFLINE_DEK, entry);
}
export async function getOfflineKek(workspaceId: string): Promise<OfflineKekEntry | null> {
  const db = await openOfflineDb();
  const raw = await idbGet<OfflineKekEntry>(db, STORE_OFFLINE_KEK, workspaceId);
  return raw ?? null;
}
export async function putOfflineKek(entry: OfflineKekEntry): Promise<void> {
  const db = await openOfflineDb();
  await idbPut(db, STORE_OFFLINE_KEK, entry);
}
export async function deleteOfflineKek(workspaceId: string): Promise<void> {
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_OFFLINE_KEK, "readwrite");
    tx.objectStore(STORE_OFFLINE_KEK).delete(workspaceId);
    tx.oncomplete = () => {
      resolve();
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}
export async function deleteOrphanedKeks(activeWorkspaceIds: Iterable<string>): Promise<void> {
  const activeWorkspaceIdSet = new Set(activeWorkspaceIds);
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_OFFLINE_KEK, "readwrite");
    const store = tx.objectStore(STORE_OFFLINE_KEK);
    const req = store.getAllKeys();
    req.onerror = () => reject(req.error);
    req.onsuccess = () => {
      for (const workspaceId of req.result as string[]) {
        if (!activeWorkspaceIdSet.has(workspaceId)) {
          store.delete(workspaceId);
        }
      }
    };
    tx.oncomplete = () => {
      resolve();
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}
