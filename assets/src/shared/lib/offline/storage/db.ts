import { openIdb } from "@/shared/lib/storage/idb";
const DB_NAME = "refmd-offline";
const DB_VERSION = 2;
export const STORE_DOCUMENT_CACHE = "document-cache";
export const STORE_PENDING_CHANGES = "pending-changes";
export const STORE_OFFLINE_DEK = "offline-dek-cache";
export const STORE_OFFLINE_KEK = "offline-kek-cache";
export const STORE_OFFLINE_DOCUMENTS = "offline-documents";
export const STORE_OFFLINE_CREATED = "offline-created";
export const STORE_OFFLINE_WORKSPACES = "offline-workspaces";
export const STORE_OFFLINE_DOCUMENT_INDEX = "offline-document-index";
let upgradeCompleted = false;
function upgradeOfflineDb(db: IDBDatabase, oldVersion: number): void {
  if (oldVersion < 1) {
    db.createObjectStore(STORE_DOCUMENT_CACHE, { keyPath: "documentId" });
    db.createObjectStore(STORE_PENDING_CHANGES, { keyPath: "documentId" });
    db.createObjectStore(STORE_OFFLINE_DEK, { keyPath: "documentId" });
    db.createObjectStore(STORE_OFFLINE_KEK, { keyPath: "workspaceId" });
    const metaStore = db.createObjectStore(STORE_OFFLINE_DOCUMENTS, { keyPath: "documentId" });
    metaStore.createIndex("by-lastAccessedAt", "lastAccessedAt");
    db.createObjectStore(STORE_OFFLINE_CREATED, { keyPath: "documentId" });
  }
  if (oldVersion < 2) {
    db.createObjectStore(STORE_OFFLINE_WORKSPACES, { keyPath: "id" });
    const indexStore = db.createObjectStore(STORE_OFFLINE_DOCUMENT_INDEX, {
      keyPath: "documentId",
    });
    indexStore.createIndex("by-workspaceId", "workspaceId");
  }
}
export async function ensureOfflineDbReady(): Promise<void> {
  if (upgradeCompleted) return;
  const db = await openIdb(DB_NAME, DB_VERSION, upgradeOfflineDb);
  db.close();
  upgradeCompleted = true;
}
export function openOfflineDb(): Promise<IDBDatabase> {
  return openIdb(DB_NAME, DB_VERSION, upgradeOfflineDb);
}
