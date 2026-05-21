import * as Y from "yjs";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import {
  deletePendingChanges,
  getDocumentCache,
  getOfflineDocumentMeta,
  getPendingChanges,
  putDocumentCache,
  putOfflineDocumentMeta,
  putPendingChanges,
  type DocumentCacheEntry,
  type PendingChangesEntry,
} from "@/shared/lib/offline/storage/store";
import { clientWarn } from "@/shared/lib/logger";
import type { CacheableDocumentState } from "./types";

const periodicFlushIntervalMs = 30000;
const flushLocks = new Map<string, boolean>();

export async function cacheDocumentState(
  documentId: string,
  workspaceId: string,
  state: CacheableDocumentState,
): Promise<void> {
  if (flushLocks.get(documentId)) return;
  flushLocks.set(documentId, true);

  let entry: DocumentCacheEntry | null = null;
  try {
    const worker = getCryptoWorker();
    const fullState = Y.encodeStateAsUpdate(state.yDoc);
    const { ciphertext, nonce } = await worker.encryptOfflineCache({
      plaintext: fullState,
      documentId,
      keyVersion: state.keyVersion,
    });
    const confirmedStateVector = state.lastSavedState
      ? Y.encodeStateVectorFromUpdate(state.lastSavedState)
      : (state._cachedConfirmedStateVector ?? Y.encodeStateVector(state.yDoc));
    entry = {
      documentId,
      workspaceId,
      encryptedState: ciphertext,
      stateNonce: nonce,
      keyVersion: state.keyVersion,
      confirmedStateVector,
      confirmedSnapshotId: state.activeSnapshotId ?? "",
      confirmedVersion: state.latestVersion,
      confirmedClocks: { ...state.confirmedClocks },
      cachedAt: Date.now(),
      updatedAt: Date.now(),
    };
    await putDocumentCache(entry);
    const existingMeta = await getOfflineDocumentMeta(documentId);
    await putOfflineDocumentMeta({
      documentId,
      workspaceId,
      encryptedTitle: existingMeta?.encryptedTitle ?? new Uint8Array(0),
      encryptedTitleNonce: existingMeta?.encryptedTitleNonce ?? new Uint8Array(0),
      lastAccessedAt: Date.now(),
      cacheSize: ciphertext.byteLength,
    });
  } catch (err) {
    clientWarn("offline_cache_document_state_failed", { documentId, error: err });
    try {
      const { checkAndEvict } = await import("@/shared/lib/offline/cache/eviction");
      await checkAndEvict();
      if (entry) {
        await putDocumentCache(entry);
        const retryMeta = await getOfflineDocumentMeta(documentId);
        await putOfflineDocumentMeta({
          documentId,
          workspaceId,
          encryptedTitle: retryMeta?.encryptedTitle ?? new Uint8Array(0),
          encryptedTitleNonce: retryMeta?.encryptedTitleNonce ?? new Uint8Array(0),
          lastAccessedAt: Date.now(),
          cacheSize: entry.encryptedState.byteLength,
        });
      }
    } catch {
      // Retry also failed
    }
  } finally {
    flushLocks.delete(documentId);
  }
}

export async function cachePendingChanges(
  documentId: string,
  state: CacheableDocumentState,
): Promise<void> {
  let pendingEntry: PendingChangesEntry | null = null;
  try {
    const confirmedVector = state.lastSavedState
      ? Y.encodeStateVectorFromUpdate(state.lastSavedState)
      : (state._cachedConfirmedStateVector ?? new Uint8Array(0));
    const diff =
      confirmedVector.length > 0
        ? Y.encodeStateAsUpdate(state.yDoc, confirmedVector)
        : Y.encodeStateAsUpdate(state.yDoc);
    if (diff.length <= 2) {
      await deletePendingChanges(documentId).catch(() => {});
      const meta = await getOfflineDocumentMeta(documentId).catch(() => null);
      if (meta) {
        const docCache = await getDocumentCache(documentId).catch(() => null);
        meta.cacheSize = docCache?.encryptedState?.byteLength ?? 0;
        await putOfflineDocumentMeta(meta).catch(() => {});
      }
      return;
    }

    const worker = getCryptoWorker();
    const { ciphertext, nonce } = await worker.encryptOfflinePending({
      plaintext: diff,
      documentId,
      keyVersion: state.keyVersion,
    });
    const now = Date.now();
    const existing = await getPendingChanges(documentId);
    pendingEntry = {
      documentId,
      encryptedDiff: ciphertext,
      diffNonce: nonce,
      keyVersion: state.keyVersion,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
      syncBlockedReason: existing?.syncBlockedReason ?? null,
      syncBlockedAt: existing?.syncBlockedAt ?? null,
    };
    await putPendingChanges(pendingEntry);
    const meta = await getOfflineDocumentMeta(documentId);
    if (meta) {
      const docCache = await getDocumentCache(documentId);
      meta.cacheSize = (docCache?.encryptedState?.byteLength ?? 0) + ciphertext.byteLength;
      await putOfflineDocumentMeta(meta);
    }
  } catch (err) {
    clientWarn("offline_cache_pending_changes_failed", { documentId, error: err });
    try {
      const { checkAndEvict } = await import("@/shared/lib/offline/cache/eviction");
      await checkAndEvict();
      if (pendingEntry) {
        await putPendingChanges(pendingEntry);
        const retryMeta = await getOfflineDocumentMeta(documentId);
        if (retryMeta) {
          const docCache = await getDocumentCache(documentId);
          retryMeta.cacheSize =
            (docCache?.encryptedState?.byteLength ?? 0) + pendingEntry.encryptedDiff.byteLength;
          await putOfflineDocumentMeta(retryMeta);
        }
      }
    } catch {
      // Retry also failed
    }
  }
}

export function flushDocumentCache(
  documentId: string,
  workspaceId: string,
  state: CacheableDocumentState,
): void {
  if (state.initialized && state.keyVersion > 0) {
    cacheDocumentState(documentId, workspaceId, state).catch(() => {});
    cachePendingChanges(documentId, state).catch(() => {});
  }
}

export function startPeriodicFlush(
  documentId: string,
  workspaceId: string,
  state: CacheableDocumentState,
): () => void {
  const interval = setInterval(() => {
    flushDocumentCache(documentId, workspaceId, state);
  }, periodicFlushIntervalMs);
  return () => clearInterval(interval);
}
