import * as Y from "yjs";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import {
  encodeCanonicalDiffAsUpdate,
  encodeCanonicalSyncedStateAsUpdate,
  encodeCanonicalStateVector,
} from "@/shared/lib/yjs/canonical-document";
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
type OfflineCacheWorker = ReturnType<typeof getCryptoWorker>;
type OfflineCacheStateKind = NonNullable<DocumentCacheEntry["encryptedStateKind"]>;

export interface OfflineCacheOptions {
  worker?: OfflineCacheWorker;
  cacheKey?: string;
}

export function resolveOfflineCacheStateKind(state: CacheableDocumentState): OfflineCacheStateKind {
  if (!state.lastSavedState) return "live";
  return encodeCanonicalDiffAsUpdate(state.yDoc, state.lastSavedState) ? "confirmed" : "live";
}

function shouldDropPendingChangesAfterBlockedDiff(cacheEntry: DocumentCacheEntry | null): boolean {
  return cacheEntry?.encryptedStateKind === "live";
}

export async function cacheDocumentState(
  documentId: string,
  workspaceId: string,
  state: CacheableDocumentState,
  options: OfflineCacheOptions = {},
): Promise<boolean> {
  const lockKey = options.cacheKey ? `${documentId}:${options.cacheKey}` : documentId;
  if (flushLocks.get(lockKey)) return false;
  flushLocks.set(lockKey, true);

  let entry: DocumentCacheEntry | null = null;
  let persisted = false;
  try {
    const worker = options.worker ?? getCryptoWorker();
    const confirmedState = state.lastSavedState;
    const encryptedStateKind = resolveOfflineCacheStateKind(state);
    const primaryState =
      encryptedStateKind === "confirmed" && confirmedState
        ? confirmedState
        : encodeCanonicalSyncedStateAsUpdate(state.yDoc);
    const primary = await worker.encryptOfflineCache({
      plaintext: primaryState,
      documentId,
      keyVersion: state.keyVersion,
      cacheKey: options.cacheKey,
    });
    const encryptedConfirmedState =
      confirmedState && encryptedStateKind === "confirmed"
        ? primary
        : confirmedState
          ? await worker.encryptOfflineCache({
              plaintext: confirmedState,
              documentId,
              keyVersion: state.keyVersion,
              cacheKey: options.cacheKey,
            })
          : null;
    const confirmedStateVector = state.lastSavedState
      ? Y.encodeStateVectorFromUpdate(state.lastSavedState)
      : (state._cachedConfirmedStateVector ?? encodeCanonicalStateVector(state.yDoc));
    entry = {
      documentId,
      workspaceId,
      encryptedState: primary.ciphertext,
      stateNonce: primary.nonce,
      encryptedStateKind,
      encryptedConfirmedState: encryptedConfirmedState?.ciphertext ?? null,
      confirmedStateNonce: encryptedConfirmedState?.nonce ?? null,
      keyVersion: state.keyVersion,
      confirmedStateVector,
      confirmedSnapshotId: state.activeSnapshotId ?? "",
      confirmedSnapshotProofHash: state.snapshotProofHash ?? null,
      confirmedSnapshotCiphertextHash: state.snapshotCiphertextHash ?? null,
      confirmedVersion: state.latestVersion,
      confirmedClocks: { ...state.confirmedClocks },
      cachedAt: Date.now(),
      updatedAt: Date.now(),
    };
    await putDocumentCache(entry);
    persisted = true;
    const existingMeta = await getOfflineDocumentMeta(documentId);
    const cacheSize =
      primary.ciphertext.byteLength + (encryptedConfirmedState?.ciphertext.byteLength ?? 0);
    await putOfflineDocumentMeta({
      documentId,
      workspaceId,
      encryptedTitle: existingMeta?.encryptedTitle ?? new Uint8Array(0),
      encryptedTitleNonce: existingMeta?.encryptedTitleNonce ?? new Uint8Array(0),
      lastAccessedAt: Date.now(),
      cacheSize,
    });
  } catch (err) {
    clientWarn("offline_cache_document_state_failed", { documentId, error: err });
    try {
      const { checkAndEvict } = await import("@/shared/lib/offline/cache/eviction");
      await checkAndEvict();
      if (entry) {
        await putDocumentCache(entry);
        persisted = true;
        const retryMeta = await getOfflineDocumentMeta(documentId);
        const cacheSize =
          entry.encryptedState.byteLength + (entry.encryptedConfirmedState?.byteLength ?? 0);
        await putOfflineDocumentMeta({
          documentId,
          workspaceId,
          encryptedTitle: retryMeta?.encryptedTitle ?? new Uint8Array(0),
          encryptedTitleNonce: retryMeta?.encryptedTitleNonce ?? new Uint8Array(0),
          lastAccessedAt: Date.now(),
          cacheSize,
        });
      }
    } catch {
      // Retry also failed
    }
  } finally {
    flushLocks.delete(lockKey);
  }
  return persisted;
}

export async function cachePendingChanges(
  documentId: string,
  state: CacheableDocumentState,
  options: OfflineCacheOptions = {},
): Promise<void> {
  let pendingEntry: PendingChangesEntry | null = null;
  try {
    if (!state.lastSavedState) {
      const cacheEntry = await getDocumentCache(documentId).catch(() => null);
      if (shouldDropPendingChangesAfterBlockedDiff(cacheEntry)) {
        await deletePendingChanges(documentId).catch(() => {});
      }
      return;
    }
    const diff = encodeCanonicalDiffAsUpdate(state.yDoc, state.lastSavedState);
    if (!diff) {
      const cacheEntry = await getDocumentCache(documentId).catch(() => null);
      clientWarn("offline_cache_pending_changes_blocked", {
        documentId,
        reason: "canonical_structural_diff_unavailable",
        cachedStateKind: cacheEntry?.encryptedStateKind ?? null,
      });
      if (shouldDropPendingChangesAfterBlockedDiff(cacheEntry)) {
        await deletePendingChanges(documentId).catch(() => {});
        const meta = await getOfflineDocumentMeta(documentId).catch(() => null);
        if (meta) {
          const docCache = await getDocumentCache(documentId).catch(() => null);
          meta.cacheSize =
            (docCache?.encryptedState?.byteLength ?? 0) +
            (docCache?.encryptedConfirmedState?.byteLength ?? 0);
          await putOfflineDocumentMeta(meta).catch(() => {});
        }
      }
      return;
    }
    if (diff.length <= 2) {
      await deletePendingChanges(documentId).catch(() => {});
      const meta = await getOfflineDocumentMeta(documentId).catch(() => null);
      if (meta) {
        const docCache = await getDocumentCache(documentId).catch(() => null);
        meta.cacheSize =
          (docCache?.encryptedState?.byteLength ?? 0) +
          (docCache?.encryptedConfirmedState?.byteLength ?? 0);
        await putOfflineDocumentMeta(meta).catch(() => {});
      }
      return;
    }

    const worker = options.worker ?? getCryptoWorker();
    const { ciphertext, nonce } = await worker.encryptOfflinePending({
      plaintext: diff,
      documentId,
      keyVersion: state.keyVersion,
      cacheKey: options.cacheKey,
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
      meta.cacheSize =
        (docCache?.encryptedState?.byteLength ?? 0) +
        (docCache?.encryptedConfirmedState?.byteLength ?? 0) +
        ciphertext.byteLength;
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
            (docCache?.encryptedState?.byteLength ?? 0) +
            (docCache?.encryptedConfirmedState?.byteLength ?? 0) +
            pendingEntry.encryptedDiff.byteLength;
          await putOfflineDocumentMeta(retryMeta);
        }
      }
    } catch {
      // Retry also failed
    }
  }
}

export async function cacheDocumentStateAndPendingChanges(
  documentId: string,
  workspaceId: string,
  state: CacheableDocumentState,
  options: OfflineCacheOptions = {},
): Promise<void> {
  const persisted = await cacheDocumentState(documentId, workspaceId, state, options);
  if (!persisted) return;
  await cachePendingChanges(documentId, state, options);
}

export function flushDocumentCache(
  documentId: string,
  workspaceId: string,
  state: CacheableDocumentState,
  options: OfflineCacheOptions = {},
): void {
  if (state.initialized && state.keyVersion > 0) {
    cacheDocumentStateAndPendingChanges(documentId, workspaceId, state, options).catch(() => {});
  }
}

export function startPeriodicFlush(
  documentId: string,
  workspaceId: string,
  state: CacheableDocumentState,
  options: OfflineCacheOptions = {},
): () => void {
  const interval = setInterval(() => {
    flushDocumentCache(documentId, workspaceId, state, options);
  }, periodicFlushIntervalMs);
  return () => clearInterval(interval);
}
