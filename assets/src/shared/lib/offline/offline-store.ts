import { openIdb, idbGet, idbPut, toArrayBuffer } from "@/shared/lib/idb";

const DB_NAME = "refmd-offline";
const DB_VERSION = 2;

const STORE_DOCUMENT_CACHE = "document-cache";
const STORE_PENDING_CHANGES = "pending-changes";
const STORE_OFFLINE_DEK = "offline-dek-cache";
const STORE_OFFLINE_KEK = "offline-kek-cache";
const STORE_OFFLINE_DOCUMENTS = "offline-documents";
const STORE_OFFLINE_CREATED = "offline-created";
const STORE_OFFLINE_WORKSPACES = "offline-workspaces";
const STORE_OFFLINE_DOCUMENT_INDEX = "offline-document-index";

const ALL_STORES = [
  STORE_DOCUMENT_CACHE,
  STORE_PENDING_CHANGES,
  STORE_OFFLINE_DEK,
  STORE_OFFLINE_KEK,
  STORE_OFFLINE_DOCUMENTS,
  STORE_OFFLINE_CREATED,
  STORE_OFFLINE_WORKSPACES,
  STORE_OFFLINE_DOCUMENT_INDEX,
] as const;

// ── Interfaces ───────────────────────────────────────────────

export interface DocumentCacheEntry {
  documentId: string;
  workspaceId: string;
  encryptedState: Uint8Array;
  stateNonce: Uint8Array;
  keyVersion: number;
  confirmedStateVector: Uint8Array;
  confirmedSnapshotId: string;
  confirmedVersion: number;
  confirmedClocks: Record<string, number>;
  cachedAt: number;
  updatedAt: number;
}

export interface PendingChangesEntry {
  documentId: string;
  encryptedDiff: Uint8Array;
  diffNonce: Uint8Array;
  keyVersion: number;
  createdAt: number;
  updatedAt: number;
}

export interface OfflineDekEntry {
  documentId: string;
  wrappedDek: ArrayBuffer;
  wrappedDekNonce: ArrayBuffer;
  keyVersion: number;
  cachedAt: number;
}

export interface OfflineKekEntry {
  workspaceId: string;
  wrappedKek: ArrayBuffer;
  wrappedKekNonce: ArrayBuffer;
  keyVersion: number;
  cachedAt: number;
}

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
}

export interface OfflineWorkspace {
  id: string;
  name: string;
  description: string;
  slug: string;
  isDefault: boolean;
  updatedAt: string;
  lastSyncedAt: number;
}

export interface OfflineDocumentIndexEntry {
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

// ── IDB serialization types ──────────────────────────────────

interface DocumentCacheIdb {
  documentId: string;
  workspaceId: string;
  encryptedState: ArrayBuffer;
  stateNonce: ArrayBuffer;
  keyVersion: number;
  confirmedStateVector: ArrayBuffer;
  confirmedSnapshotId: string;
  confirmedVersion: number;
  confirmedClocks: Record<string, number>;
  cachedAt: number;
  updatedAt: number;
}

interface PendingChangesIdb {
  documentId: string;
  encryptedDiff: ArrayBuffer;
  diffNonce: ArrayBuffer;
  keyVersion: number;
  createdAt: number;
  updatedAt: number;
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
}

// ── DB open ──────────────────────────────────────────────────

let upgradeCompleted = false;

export async function ensureOfflineDbReady(): Promise<void> {
  if (upgradeCompleted) return;
  const db = await openIdb(DB_NAME, DB_VERSION, (db, oldVersion) => {
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
  });
  db.close();
  upgradeCompleted = true;
}

function openOfflineDb(): Promise<IDBDatabase> {
  return openIdb(DB_NAME, DB_VERSION, (db, oldVersion) => {
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
  });
}

// ── document-cache ───────────────────────────────────────────

function serializeDocumentCache(entry: DocumentCacheEntry): DocumentCacheIdb {
  return {
    documentId: entry.documentId,
    workspaceId: entry.workspaceId,
    encryptedState: toArrayBuffer(entry.encryptedState),
    stateNonce: toArrayBuffer(entry.stateNonce),
    keyVersion: entry.keyVersion,
    confirmedStateVector: toArrayBuffer(entry.confirmedStateVector),
    confirmedSnapshotId: entry.confirmedSnapshotId,
    confirmedVersion: entry.confirmedVersion,
    confirmedClocks: entry.confirmedClocks,
    cachedAt: entry.cachedAt,
    updatedAt: entry.updatedAt,
  };
}

function deserializeDocumentCache(raw: DocumentCacheIdb): DocumentCacheEntry {
  return {
    documentId: raw.documentId,
    workspaceId: raw.workspaceId,
    encryptedState: new Uint8Array(raw.encryptedState),
    stateNonce: new Uint8Array(raw.stateNonce),
    keyVersion: raw.keyVersion,
    confirmedStateVector: new Uint8Array(raw.confirmedStateVector),
    confirmedSnapshotId: raw.confirmedSnapshotId,
    confirmedVersion: raw.confirmedVersion,
    confirmedClocks: raw.confirmedClocks,
    cachedAt: raw.cachedAt,
    updatedAt: raw.updatedAt,
  };
}

export async function getDocumentCache(documentId: string): Promise<DocumentCacheEntry | null> {
  const db = await openOfflineDb();
  const raw = await idbGet<DocumentCacheIdb>(db, STORE_DOCUMENT_CACHE, documentId);
  return raw ? deserializeDocumentCache(raw) : null;
}

export async function putDocumentCache(entry: DocumentCacheEntry): Promise<void> {
  const db = await openOfflineDb();
  await idbPut(db, STORE_DOCUMENT_CACHE, serializeDocumentCache(entry));
}

export async function deleteDocumentCache(documentId: string): Promise<void> {
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_DOCUMENT_CACHE, "readwrite");
    tx.objectStore(STORE_DOCUMENT_CACHE).delete(documentId);
    tx.oncomplete = () => {
      resolve();
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}

// ── pending-changes ──────────────────────────────────────────

function serializePendingChanges(entry: PendingChangesEntry): PendingChangesIdb {
  return {
    documentId: entry.documentId,
    encryptedDiff: toArrayBuffer(entry.encryptedDiff),
    diffNonce: toArrayBuffer(entry.diffNonce),
    keyVersion: entry.keyVersion,
    createdAt: entry.createdAt,
    updatedAt: entry.updatedAt,
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

export async function hasPendingChanges(documentId: string): Promise<boolean> {
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_PENDING_CHANGES, "readonly");
    const req = tx.objectStore(STORE_PENDING_CHANGES).count(documentId);
    req.onerror = () => reject(req.error);
    tx.oncomplete = () => {
      resolve(req.result > 0);
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

// ── offline-dek-cache ────────────────────────────────────────

export async function getOfflineDek(documentId: string): Promise<OfflineDekEntry | null> {
  const db = await openOfflineDb();
  const raw = await idbGet<OfflineDekEntry>(db, STORE_OFFLINE_DEK, documentId);
  return raw ?? null;
}

export async function putOfflineDek(entry: OfflineDekEntry): Promise<void> {
  const db = await openOfflineDb();
  await idbPut(db, STORE_OFFLINE_DEK, entry);
}

export async function deleteOfflineDek(documentId: string): Promise<void> {
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_OFFLINE_DEK, "readwrite");
    tx.objectStore(STORE_OFFLINE_DEK).delete(documentId);
    tx.oncomplete = () => {
      resolve();
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}

// ── offline-kek-cache ────────────────────────────────────────

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

// ── offline-documents ────────────────────────────────────────

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

export async function deleteOfflineDocumentMeta(documentId: string): Promise<void> {
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_OFFLINE_DOCUMENTS, "readwrite");
    tx.objectStore(STORE_OFFLINE_DOCUMENTS).delete(documentId);
    tx.oncomplete = () => {
      resolve();
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
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

// ── offline-created ──────────────────────────────────────────

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
  };
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

export async function getAllOfflineKekWorkspaceIds(): Promise<string[]> {
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_OFFLINE_KEK, "readonly");
    const req = tx.objectStore(STORE_OFFLINE_KEK).getAllKeys();
    req.onerror = () => reject(req.error);
    tx.oncomplete = () => {
      resolve(req.result as string[]);
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}

// ── Utility ──────────────────────────────────────────────────

export async function getTotalCacheSize(): Promise<number> {
  const metas = await getAllOfflineDocumentMetas();
  return metas.reduce((sum, m) => sum + m.cacheSize, 0);
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
      const c = cursor.result;
      if (!c || candidates.length >= count) {
        return;
      }
      const meta = c.value as OfflineDocumentMeta;
      const check = pendingStore.count(meta.documentId);
      check.onsuccess = () => {
        if (check.result === 0) {
          candidates.push(meta.documentId);
        }
        if (candidates.length < count) {
          c.continue();
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

export async function clearAllOfflineStores(): Promise<void> {
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([...ALL_STORES], "readwrite");
    for (const store of ALL_STORES) {
      tx.objectStore(store).clear();
    }
    tx.oncomplete = () => {
      resolve();
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

// ── offline-workspaces ───────────────────────────────────────

export async function putOfflineWorkspaces(workspaces: OfflineWorkspace[]): Promise<void> {
  const db = await openOfflineDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_OFFLINE_WORKSPACES, "readwrite");
    const store = tx.objectStore(STORE_OFFLINE_WORKSPACES);
    store.clear();
    for (const ws of workspaces) {
      store.put(ws);
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

// ── offline-document-index ───────────────────────────────────

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
