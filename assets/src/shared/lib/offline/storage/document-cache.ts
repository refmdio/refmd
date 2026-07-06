import { idbGet, idbPut, toArrayBuffer } from "@/shared/lib/storage/idb";
import { openOfflineDb, STORE_DOCUMENT_CACHE } from "./db";

export interface DocumentCacheEntry {
  documentId: string;
  workspaceId: string;
  encryptedState: Uint8Array;
  stateNonce: Uint8Array;
  encryptedStateKind?: "confirmed" | "live";
  encryptedConfirmedState?: Uint8Array | null;
  confirmedStateNonce?: Uint8Array | null;
  keyVersion: number;
  confirmedStateVector: Uint8Array;
  confirmedSnapshotId: string;
  confirmedSnapshotProofHash?: string | null;
  confirmedSnapshotCiphertextHash?: string | null;
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
  encryptedStateKind?: "confirmed" | "live";
  encryptedConfirmedState?: ArrayBuffer | null;
  confirmedStateNonce?: ArrayBuffer | null;
  keyVersion: number;
  confirmedStateVector: ArrayBuffer;
  confirmedSnapshotId: string;
  confirmedSnapshotProofHash?: string | null;
  confirmedSnapshotCiphertextHash?: string | null;
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
    encryptedStateKind: entry.encryptedStateKind,
    encryptedConfirmedState: entry.encryptedConfirmedState
      ? toArrayBuffer(entry.encryptedConfirmedState)
      : null,
    confirmedStateNonce: entry.confirmedStateNonce
      ? toArrayBuffer(entry.confirmedStateNonce)
      : null,
    keyVersion: entry.keyVersion,
    confirmedStateVector: toArrayBuffer(entry.confirmedStateVector),
    confirmedSnapshotId: entry.confirmedSnapshotId,
    confirmedSnapshotProofHash: entry.confirmedSnapshotProofHash ?? null,
    confirmedSnapshotCiphertextHash: entry.confirmedSnapshotCiphertextHash ?? null,
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
    encryptedStateKind: raw.encryptedStateKind,
    encryptedConfirmedState: raw.encryptedConfirmedState
      ? new Uint8Array(raw.encryptedConfirmedState)
      : null,
    confirmedStateNonce: raw.confirmedStateNonce ? new Uint8Array(raw.confirmedStateNonce) : null,
    keyVersion: raw.keyVersion,
    confirmedStateVector: new Uint8Array(raw.confirmedStateVector),
    confirmedSnapshotId: raw.confirmedSnapshotId,
    confirmedSnapshotProofHash: raw.confirmedSnapshotProofHash ?? null,
    confirmedSnapshotCiphertextHash: raw.confirmedSnapshotCiphertextHash ?? null,
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
