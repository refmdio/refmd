import { idbGet, idbPut, toArrayBuffer } from "@/shared/lib/storage/idb";
import {
  openOfflineDb,
  STORE_OFFLINE_CREATED,
  STORE_OFFLINE_DOCUMENT_INDEX,
  STORE_OFFLINE_DOCUMENTS,
  STORE_OFFLINE_WORKSPACES,
} from "./db";
export interface OfflineDocumentMeta {
  documentId: string;
  workspaceId: string;
  encryptedTitle: Uint8Array;
  encryptedTitleNonce: Uint8Array;
  lastAccessedAt: number;
  cacheSize: number;
}
export interface OfflineCreatedDocument {
  documentId: string;
  workspaceId: string;
  parentId: string | null;
  encryptedTitle: Uint8Array;
  encryptedTitleNonce: Uint8Array;
  encryptedTitleKeyVersion: number;
  wrappedDek: ArrayBuffer;
  wrappedDekNonce: ArrayBuffer;
  dekKeyVersion: number;
  kekWrappedDek: Uint8Array;
  kekWrappedDekNonce: Uint8Array;
  kekVersion: number;
  encryptedState: Uint8Array;
  stateNonce: Uint8Array;
  createdAt: number;
  syncBlockedReason?: OfflineCreatedSyncBlockReason | null;
  syncBlockedAt?: number | null;
}
export type OfflineCreatedSyncBlockReason =
  | "not_a_member"
  | "permission_denied"
  | "workspace_unavailable";
interface OfflineWorkspace {
  id: string;
  name: string;
  description: string;
  slug: string;
  isDefault: boolean;
  updatedAt: string;
  lastSyncedAt: number;
}
interface OfflineDocumentIndexEntry {
  documentId: string;
  workspaceId: string;
  parentId: string | null;
  position: number;
  docType: "document" | "folder";
  folderTitle: string | null;
  archivedAt: string | null;
  isEncrypted: boolean;
  updatedAt: string;
}
interface OfflineDocumentMetaIdb {
  documentId: string;
  workspaceId: string;
  encryptedTitle: ArrayBuffer;
  encryptedTitleNonce: ArrayBuffer;
  lastAccessedAt: number;
  cacheSize: number;
}
interface OfflineCreatedIdb {
  documentId: string;
  workspaceId: string;
  parentId: string | null;
  encryptedTitle: ArrayBuffer;
  encryptedTitleNonce: ArrayBuffer;
  encryptedTitleKeyVersion: number;
  wrappedDek: ArrayBuffer;
  wrappedDekNonce: ArrayBuffer;
  dekKeyVersion: number;
  kekWrappedDek: ArrayBuffer;
  kekWrappedDekNonce: ArrayBuffer;
  kekVersion: number;
  encryptedState: ArrayBuffer;
  stateNonce: ArrayBuffer;
  createdAt: number;
  syncBlockedReason?: OfflineCreatedSyncBlockReason;
  syncBlockedAt?: number;
}
function serializeDocumentMeta(entry: OfflineDocumentMeta): OfflineDocumentMetaIdb {
  return {
    documentId: entry.documentId,
    workspaceId: entry.workspaceId,
    encryptedTitle: toArrayBuffer(entry.encryptedTitle),
    encryptedTitleNonce: toArrayBuffer(entry.encryptedTitleNonce),
    lastAccessedAt: entry.lastAccessedAt,
    cacheSize: entry.cacheSize,
  };
}
function deserializeDocumentMeta(raw: OfflineDocumentMetaIdb): OfflineDocumentMeta {
  return {
    documentId: raw.documentId,
    workspaceId: raw.workspaceId,
    encryptedTitle: new Uint8Array(raw.encryptedTitle),
    encryptedTitleNonce: new Uint8Array(raw.encryptedTitleNonce),
    lastAccessedAt: raw.lastAccessedAt,
    cacheSize: raw.cacheSize,
  };
}
function serializeOfflineCreated(entry: OfflineCreatedDocument): OfflineCreatedIdb {
  return {
    documentId: entry.documentId,
    workspaceId: entry.workspaceId,
    parentId: entry.parentId,
    encryptedTitle: toArrayBuffer(entry.encryptedTitle),
    encryptedTitleNonce: toArrayBuffer(entry.encryptedTitleNonce),
    encryptedTitleKeyVersion: entry.encryptedTitleKeyVersion,
    wrappedDek: entry.wrappedDek,
    wrappedDekNonce: entry.wrappedDekNonce,
    dekKeyVersion: entry.dekKeyVersion,
    kekWrappedDek: toArrayBuffer(entry.kekWrappedDek),
    kekWrappedDekNonce: toArrayBuffer(entry.kekWrappedDekNonce),
    kekVersion: entry.kekVersion,
    encryptedState: toArrayBuffer(entry.encryptedState),
    stateNonce: toArrayBuffer(entry.stateNonce),
    createdAt: entry.createdAt,
    syncBlockedReason: entry.syncBlockedReason ?? undefined,
    syncBlockedAt: entry.syncBlockedAt ?? undefined,
  };
}
function deserializeOfflineCreated(raw: OfflineCreatedIdb): OfflineCreatedDocument {
  return {
    documentId: raw.documentId,
    workspaceId: raw.workspaceId,
    parentId: raw.parentId,
    encryptedTitle: new Uint8Array(raw.encryptedTitle),
    encryptedTitleNonce: new Uint8Array(raw.encryptedTitleNonce),
    encryptedTitleKeyVersion: raw.encryptedTitleKeyVersion,
    wrappedDek: raw.wrappedDek,
    wrappedDekNonce: raw.wrappedDekNonce,
    dekKeyVersion: raw.dekKeyVersion,
    kekWrappedDek: new Uint8Array(raw.kekWrappedDek),
    kekWrappedDekNonce: new Uint8Array(raw.kekWrappedDekNonce),
    kekVersion: raw.kekVersion,
    encryptedState: new Uint8Array(raw.encryptedState),
    stateNonce: new Uint8Array(raw.stateNonce),
    createdAt: raw.createdAt,
    syncBlockedReason: raw.syncBlockedReason ?? null,
    syncBlockedAt: raw.syncBlockedAt ?? null,
  };
}
export async function getOfflineDocumentMeta(
  documentId: string,
): Promise<OfflineDocumentMeta | null> {
  const db = await openOfflineDb();
  const raw = await idbGet<OfflineDocumentMetaIdb>(db, STORE_OFFLINE_DOCUMENTS, documentId);
  return raw ? deserializeDocumentMeta(raw) : null;
}
export async function putOfflineDocumentMeta(entry: OfflineDocumentMeta): Promise<void> {
  const db = await openOfflineDb();
  await idbPut(db, STORE_OFFLINE_DOCUMENTS, serializeDocumentMeta(entry));
}
export async function getAllOfflineDocumentMetas(): Promise<OfflineDocumentMeta[]> {
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_OFFLINE_DOCUMENTS, "readonly");
    const req = tx.objectStore(STORE_OFFLINE_DOCUMENTS).getAll();
    req.onerror = () => reject(req.error);
    tx.oncomplete = () => {
      resolve((req.result as OfflineDocumentMetaIdb[]).map(deserializeDocumentMeta));
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}
export async function getOfflineCreated(
  documentId: string,
): Promise<OfflineCreatedDocument | null> {
  const db = await openOfflineDb();
  const raw = await idbGet<OfflineCreatedIdb>(db, STORE_OFFLINE_CREATED, documentId);
  return raw ? deserializeOfflineCreated(raw) : null;
}
export async function putOfflineCreated(entry: OfflineCreatedDocument): Promise<void> {
  const db = await openOfflineDb();
  await idbPut(db, STORE_OFFLINE_CREATED, serializeOfflineCreated(entry));
}
export async function blockOfflineCreatedSync(
  documentId: string,
  reason: OfflineCreatedSyncBlockReason,
): Promise<void> {
  const existing = await getOfflineCreated(documentId);
  if (!existing) return;
  await putOfflineCreated({
    ...existing,
    syncBlockedReason: reason,
    syncBlockedAt: Date.now(),
  });
}
export async function deleteOfflineCreated(documentId: string): Promise<void> {
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_OFFLINE_CREATED, "readwrite");
    tx.objectStore(STORE_OFFLINE_CREATED).delete(documentId);
    tx.oncomplete = () => {
      resolve();
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}
export async function getAllOfflineCreated(): Promise<OfflineCreatedDocument[]> {
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_OFFLINE_CREATED, "readonly");
    const req = tx.objectStore(STORE_OFFLINE_CREATED).getAll();
    req.onerror = () => reject(req.error);
    tx.oncomplete = () => {
      resolve((req.result as OfflineCreatedIdb[]).map(deserializeOfflineCreated));
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}
export async function putOfflineWorkspaces(workspaces: OfflineWorkspace[]): Promise<void> {
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_OFFLINE_WORKSPACES, "readwrite");
    const store = tx.objectStore(STORE_OFFLINE_WORKSPACES);
    store.clear();
    for (const workspace of workspaces) {
      store.put(workspace);
    }
    tx.oncomplete = () => {
      resolve();
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}
export async function getOfflineWorkspaces(): Promise<OfflineWorkspace[]> {
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_OFFLINE_WORKSPACES, "readonly");
    const req = tx.objectStore(STORE_OFFLINE_WORKSPACES).getAll();
    req.onerror = () => reject(req.error);
    tx.oncomplete = () => {
      resolve(req.result as OfflineWorkspace[]);
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}
export async function putOfflineDocumentIndex(
  workspaceId: string,
  entries: OfflineDocumentIndexEntry[],
): Promise<void> {
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_OFFLINE_DOCUMENT_INDEX, "readwrite");
    const store = tx.objectStore(STORE_OFFLINE_DOCUMENT_INDEX);
    const index = store.index("by-workspaceId");
    const delReq = index.openKeyCursor(IDBKeyRange.only(workspaceId));
    delReq.onsuccess = () => {
      const cursor = delReq.result;
      if (cursor) {
        store.delete(cursor.primaryKey);
        cursor.continue();
      } else {
        for (const entry of entries) {
          store.put(entry);
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
export async function getOfflineDocumentIndex(
  workspaceId: string,
): Promise<OfflineDocumentIndexEntry[]> {
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_OFFLINE_DOCUMENT_INDEX, "readonly");
    const index = tx.objectStore(STORE_OFFLINE_DOCUMENT_INDEX).index("by-workspaceId");
    const req = index.getAll(workspaceId);
    req.onerror = () => reject(req.error);
    tx.oncomplete = () => {
      resolve(req.result as OfflineDocumentIndexEntry[]);
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}
