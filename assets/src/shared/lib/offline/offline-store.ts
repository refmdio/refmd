import type { OfflineDocumentMeta } from "./offline-store-meta";
import {
  openOfflineDb,
  STORE_DOCUMENT_CACHE,
  STORE_OFFLINE_DEK,
  STORE_OFFLINE_DOCUMENTS,
  STORE_PENDING_CHANGES,
} from "./offline-store-db";
import { getAllOfflineDocumentMetas } from "./offline-store-meta";
export { ensureOfflineDbReady } from "./offline-store-db";
export type { DocumentCacheEntry } from "./offline-store-document-cache";
export { getDocumentCache, putDocumentCache } from "./offline-store-document-cache";
export {
  deleteOfflineKek,
  deleteOrphanedKeks,
  getOfflineDek,
  getOfflineKek,
  putOfflineDek,
  putOfflineKek,
} from "./offline-store-keys";
export type { OfflineCreatedDocument } from "./offline-store-meta";
export {
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
} from "./offline-store-meta";
export type { PendingChangesEntry, PendingSyncBlockReason } from "./offline-store-pending";
export {
  blockPendingChangesSync,
  deletePendingChanges,
  getAllPendingChanges,
  getPendingChanges,
  putPendingChanges,
} from "./offline-store-pending";
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
    // Design: eviction deletes document-cache, pending-changes, offline-dek-cache only.
    // offline-documents metadata is preserved (title, lastAccessedAt for listing/management).
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
