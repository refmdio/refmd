import { idbGet, idbPut, toArrayBuffer } from "@/shared/lib/idb";
import { openOfflineDb, STORE_DOCUMENT_CACHE } from "./offline-store-db";

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
