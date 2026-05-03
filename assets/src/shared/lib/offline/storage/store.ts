import type { OfflineDocumentMeta } from "./meta";
import {
  openOfflineDb,
  STORE_DOCUMENT_CACHE,
  STORE_OFFLINE_DEK,
  STORE_OFFLINE_DOCUMENTS,
  STORE_PENDING_CHANGES,
} from "./db";
import { getAllOfflineDocumentMetas } from "./meta";
export { ensureOfflineDbReady } from "./db";
export type { DocumentCacheEntry } from "./document-cache";
export { getDocumentCache, putDocumentCache } from "./document-cache";
export {
  deleteOfflineKek,
  deleteOrphanedKeks,
  getOfflineDek,
  getOfflineKek,
  putOfflineDek,
  putOfflineKek,
} from "./keys";
export type { OfflineCreatedDocument, OfflineCreatedSyncBlockReason } from "./meta";
export {
  blockOfflineCreatedSync,
  deleteOfflineCreated,
  getAllOfflineCreated,
  getAllOfflineDocumentMetas,
  getOfflineCreated,
  getOfflineDocumentIndex,
  getOfflineDocumentMeta,
  getOfflineWorkspaces,
  putOfflineCreated,
  putOfflineDocumentIndex,
  putOfflineDocumentMeta,
  putOfflineWorkspaces,
} from "./meta";
export type { PendingChangesEntry, PendingSyncBlockReason } from "./pending";
export {
  blockPendingChangesSync,
  deletePendingChanges,
  getAllPendingChanges,
  getPendingChanges,
  putPendingChanges,
} from "./pending";
export async function getTotalCacheSize(): Promise<number> {
  const metas = await getAllOfflineDocumentMetas();
  return metas.reduce((sum, meta) => sum + meta.cacheSize, 0);
}
export async function getEvictionCandidates(count: number): Promise<string[]> {
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([STORE_OFFLINE_DOCUMENTS, STORE_PENDING_CHANGES], "readonly");
    const metaStore = tx.objectStore(STORE_OFFLINE_DOCUMENTS);
    const pendingStore = tx.objectStore(STORE_PENDING_CHANGES);
    const index = metaStore.index("by-lastAccessedAt");
    const candidates: string[] = [];
    const cursor = index.openCursor();
    cursor.onsuccess = () => {
      const current = cursor.result;
      if (!current || candidates.length >= count) {
        return;
      }
      const meta = current.value as OfflineDocumentMeta;
      const check = pendingStore.count(meta.documentId);
      check.onsuccess = () => {
        if (check.result === 0) {
          candidates.push(meta.documentId);
        }
        if (candidates.length < count) {
          current.continue();
        }
      };
    };
    tx.oncomplete = () => {
      resolve(candidates);
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}
export async function deleteDocumentOfflineData(documentId: string): Promise<void> {
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    // Eviction removes cached content but keeps lightweight metadata for listing.
    const tx = db.transaction(
      [STORE_DOCUMENT_CACHE, STORE_PENDING_CHANGES, STORE_OFFLINE_DEK],
      "readwrite",
    );
    tx.objectStore(STORE_DOCUMENT_CACHE).delete(documentId);
    tx.objectStore(STORE_PENDING_CHANGES).delete(documentId);
    tx.objectStore(STORE_OFFLINE_DEK).delete(documentId);
    tx.oncomplete = () => {
      resolve();
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}
