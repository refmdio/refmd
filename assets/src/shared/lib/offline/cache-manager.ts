import * as Y from "yjs";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { buildOfflineDocumentCacheAad } from "@/shared/lib/crypto/aad";
import {
  putDocumentCache,
  putPendingChanges,
  deletePendingChanges,
  putOfflineDek,
  putOfflineKek,
  putOfflineDocumentMeta,
  getOfflineDocumentMeta,
  getDocumentCache,
  getPendingChanges,
  getOfflineDek,
  getOfflineKek,
  type DocumentCacheEntry,
  type PendingChangesEntry,
} from "./offline-store";

const PERIODIC_FLUSH_INTERVAL_MS = 30_000;
const flushLocks = new Map<string, boolean>();

export interface CacheableDocumentState {
  yDoc: Y.Doc;
  keyVersion: number;
  activeSnapshotId: string | null;
  latestVersion: number;
  confirmedClocks: Record<string, number>;
  lastSavedState: Uint8Array | null;
  initialized: boolean;
  // Cached confirmed state vector for offline pending diff computation.
  // Set from document-cache entry during offline recovery when lastSavedState is unavailable.
  _cachedConfirmedStateVector?: Uint8Array | null;
}

// ── Write path (caching) ─────────────────────────────────────

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

    // Update metadata (lastAccessedAt, cacheSize).
    // Title is stored separately via cacheOfflineTitle when title decryption succeeds.
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
    console.warn("[offline-cache] Failed to cache document state:", documentId, err);
    // Attempt eviction on quota failure, then retry once
    try {
      const { checkAndEvict } = await import("./lru-eviction");
      await checkAndEvict();
      if (entry) await putDocumentCache(entry);
    } catch {
      // Retry also failed
    }
  } finally {
    flushLocks.set(documentId, false);
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

    // Trivial diff (no real changes) — remove any stale pending entry
    if (diff.length <= 2) {
      await deletePendingChanges(documentId).catch(() => {});
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

    // Update cacheSize in offline-documents to include pending changes
    const meta = await getOfflineDocumentMeta(documentId);
    if (meta) {
      const docCache = await getDocumentCache(documentId);
      meta.cacheSize = (docCache?.encryptedState?.byteLength ?? 0) + ciphertext.byteLength;
      await putOfflineDocumentMeta(meta);
    }
  } catch (err) {
    console.warn("[offline-cache] Failed to cache pending changes:", documentId, err);
    try {
      const { checkAndEvict } = await import("./lru-eviction");
      await checkAndEvict();
      if (pendingEntry) await putPendingChanges(pendingEntry);
    } catch {
      // Retry also failed
    }
  }
}

export async function cacheDek(documentId: string, keyVersion: number): Promise<void> {
  try {
    const worker = getCryptoWorker();
    const { ciphertext, iv } = await worker.wrapDekForOffline({ documentId, keyVersion });
    await putOfflineDek({
      documentId,
      wrappedDek: ciphertext,
      wrappedDekNonce: iv,
      keyVersion,
      cachedAt: Date.now(),
    });
  } catch (err) {
    console.warn("[offline-cache] Failed to cache DEK:", documentId, err);
  }
}

export async function cacheKek(workspaceId: string, keyVersion: number): Promise<void> {
  try {
    const worker = getCryptoWorker();
    const { ciphertext, iv } = await worker.wrapKekForOffline({ workspaceId, keyVersion });
    await putOfflineKek({
      workspaceId,
      wrappedKek: ciphertext,
      wrappedKekNonce: iv,
      keyVersion,
      cachedAt: Date.now(),
    });
  } catch (err) {
    console.warn("[offline-cache] Failed to cache KEK:", workspaceId, err);
  }
}

export async function cacheOfflineTitle(
  documentId: string,
  workspaceId: string,
  title: string,
): Promise<void> {
  try {
    const worker = getCryptoWorker();
    const titleAad = buildOfflineDocumentCacheAad(documentId, 0);
    const { ciphertext, iv } = await worker.wrapWithDsk({
      plaintext: new TextEncoder().encode(title),
      aad: titleAad,
    });
    const existing = await getOfflineDocumentMeta(documentId);
    await putOfflineDocumentMeta({
      documentId,
      workspaceId,
      encryptedTitle: new Uint8Array(ciphertext),
      encryptedTitleNonce: new Uint8Array(iv),
      lastAccessedAt: existing?.lastAccessedAt ?? Date.now(),
      cacheSize: existing?.cacheSize ?? 0,
    });
  } catch {
    // Best effort
  }
}

// ── Periodic flush ───────────────────────────────────────────

export function startPeriodicFlush(
  documentId: string,
  workspaceId: string,
  state: CacheableDocumentState,
): () => void {
  const interval = setInterval(() => {
    if (state.initialized && state.keyVersion > 0) {
      cacheDocumentState(documentId, workspaceId, state).catch(() => {});
      cachePendingChanges(documentId, state).catch(() => {});
    }
  }, PERIODIC_FLUSH_INTERVAL_MS);

  return () => clearInterval(interval);
}

// ── Read path (recovery) ─────────────────────────────────────

export interface RecoveredDocumentState {
  yDoc: Y.Doc;
  confirmedBaseState: Uint8Array | null;
  confirmedStateVector: Uint8Array | null;
  confirmedSnapshotId: string;
  confirmedClocks: Record<string, number>;
  confirmedVersion: number;
  keyVersion: number;
  workspaceId: string;
  hasPendingChanges: boolean;
}

export async function recoverDocumentFromCache(
  documentId: string,
): Promise<RecoveredDocumentState | null> {
  const dekEntry = await getOfflineDek(documentId);
  if (!dekEntry) return null;

  const cacheEntry = await getDocumentCache(documentId);

  // If no document-cache, try offline-created (newly created offline documents)
  if (!cacheEntry) {
    const { getOfflineCreated } = await import("./offline-store");
    const created = await getOfflineCreated(documentId);
    if (!created) return null;

    const worker = getCryptoWorker();
    await worker.unwrapDekFromOffline({
      ciphertext: dekEntry.wrappedDek,
      iv: dekEntry.wrappedDekNonce,
      documentId,
      keyVersion: dekEntry.keyVersion,
      isActive: true,
    });

    const yDoc = new Y.Doc();
    // offline-created encryptedState may be empty (new document)
    if (created.encryptedState.length > 0) {
      const decrypted = await worker.decryptOfflineCache({
        ciphertext: created.encryptedState,
        nonce: created.stateNonce,
        documentId,
        keyVersion: created.dekKeyVersion,
      });
      if (decrypted.length > 0) Y.applyUpdate(yDoc, decrypted);
    }

    // Also apply pending changes if any
    const pendingEntry = await getPendingChanges(documentId);
    if (pendingEntry) {
      const decryptedDiff = await worker.decryptOfflinePending({
        ciphertext: pendingEntry.encryptedDiff,
        nonce: pendingEntry.diffNonce,
        documentId,
        keyVersion: pendingEntry.keyVersion,
      });
      Y.applyUpdate(yDoc, decryptedDiff);
    }

    return {
      yDoc,
      confirmedBaseState: new Uint8Array(0),
      confirmedStateVector: null,
      confirmedSnapshotId: "",
      confirmedClocks: {},
      confirmedVersion: 0,
      keyVersion: created.dekKeyVersion,
      workspaceId: created.workspaceId,
      hasPendingChanges: !!pendingEntry,
    };
  }

  const worker = getCryptoWorker();

  // Restore KEK first if needed (for potential DEK re-fetch later)
  const kekEntry = await getOfflineKek(cacheEntry.workspaceId);
  if (kekEntry) {
    await worker.unwrapKekFromOffline({
      ciphertext: kekEntry.wrappedKek,
      iv: kekEntry.wrappedKekNonce,
      workspaceId: kekEntry.workspaceId,
      keyVersion: kekEntry.keyVersion,
      isActive: true,
    });
  }

  // Restore DEK
  await worker.unwrapDekFromOffline({
    ciphertext: dekEntry.wrappedDek,
    iv: dekEntry.wrappedDekNonce,
    documentId,
    keyVersion: dekEntry.keyVersion,
    isActive: true,
  });

  // Decrypt document state (full Y.Doc including unconfirmed changes at flush time)
  const decryptedState = await worker.decryptOfflineCache({
    ciphertext: cacheEntry.encryptedState,
    nonce: cacheEntry.stateNonce,
    documentId,
    keyVersion: cacheEntry.keyVersion,
  });

  // Create and populate Y.Doc
  const yDoc = new Y.Doc();
  Y.applyUpdate(yDoc, decryptedState);

  // Apply pending changes (idempotent — may contain changes newer than last cache flush)
  let hasPending = false;
  const pendingEntry = await getPendingChanges(documentId);
  if (pendingEntry) {
    const decryptedDiff = await worker.decryptOfflinePending({
      ciphertext: pendingEntry.encryptedDiff,
      nonce: pendingEntry.diffNonce,
      documentId,
      keyVersion: pendingEntry.keyVersion,
    });
    Y.applyUpdate(yDoc, decryptedDiff);
    hasPending = true;
  }

  return {
    yDoc,
    // Full Y.Doc state includes unconfirmed changes; confirmed-only state
    // cannot be extracted. Set to null — on reconnect, handleDocumentMessage
    // provides fresh lastSavedState from server.
    confirmedBaseState: null,
    confirmedStateVector: cacheEntry.confirmedStateVector,
    confirmedSnapshotId: cacheEntry.confirmedSnapshotId,
    confirmedClocks: cacheEntry.confirmedClocks,
    confirmedVersion: cacheEntry.confirmedVersion,
    keyVersion: cacheEntry.keyVersion,
    workspaceId: cacheEntry.workspaceId,
    hasPendingChanges: hasPending,
  };
}

export async function recoverKekFromCache(workspaceId: string): Promise<boolean> {
  const kekEntry = await getOfflineKek(workspaceId);
  if (!kekEntry) return false;

  const worker = getCryptoWorker();
  await worker.unwrapKekFromOffline({
    ciphertext: kekEntry.wrappedKek,
    iv: kekEntry.wrappedKekNonce,
    workspaceId,
    keyVersion: kekEntry.keyVersion,
    isActive: true,
  });
  return true;
}
