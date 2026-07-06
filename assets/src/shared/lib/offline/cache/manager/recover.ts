import * as Y from "yjs";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { encodeCanonicalSyncedStateAsUpdate } from "@/shared/lib/yjs/canonical-document";
import {
  getDocumentCache,
  getOfflineDek,
  getOfflineKek,
  getPendingChanges,
} from "@/shared/lib/offline/storage/store";
import {
  shouldReplayCachedPendingChanges,
  shouldTreatCachedStateAsConfirmedBase,
} from "./pending-replay";
import type { RecoveredDocumentState } from "./types";
type OfflineCacheWorker = ReturnType<typeof getCryptoWorker>;

export interface RecoverDocumentCacheOptions {
  worker?: OfflineCacheWorker;
  cacheKey?: string;
  includePendingChanges?: boolean;
  keyVersion?: number;
  requireOfflineDek?: boolean;
}

export async function recoverDocumentFromCache(
  documentId: string,
  options: RecoverDocumentCacheOptions = {},
): Promise<RecoveredDocumentState | null> {
  const requireOfflineDek = options.requireOfflineDek ?? !options.cacheKey;
  const includePendingChanges = options.includePendingChanges ?? true;
  const dekEntry = requireOfflineDek ? await getOfflineDek(documentId) : null;
  if (requireOfflineDek && !dekEntry) return null;

  const cacheEntry = await getDocumentCache(documentId);
  if (!cacheEntry) {
    if (!dekEntry) return null;
    const { getOfflineCreated } = await import("@/shared/lib/offline/storage/store");
    const created = await getOfflineCreated(documentId);
    if (!created) return null;

    const worker = options.worker ?? getCryptoWorker();
    await worker.restoreDekFromOffline({
      documentId,
      keyVersion: dekEntry.keyVersion,
      isActive: true,
      cacheKey: options.cacheKey,
    });
    const yDoc = new Y.Doc();
    if (created.encryptedState.length > 0) {
      const decrypted = await worker.decryptOfflineCache({
        ciphertext: created.encryptedState,
        nonce: created.stateNonce,
        documentId,
        keyVersion: created.dekKeyVersion,
        cacheKey: options.cacheKey,
      });
      if (decrypted.length > 0) Y.applyUpdate(yDoc, decrypted);
    }
    const pendingEntry =
      includePendingChanges && shouldReplayCachedPendingChanges(null, false)
        ? await getPendingChanges(documentId)
        : null;
    if (pendingEntry) {
      const decryptedDiff = await worker.decryptOfflinePending({
        ciphertext: pendingEntry.encryptedDiff,
        nonce: pendingEntry.diffNonce,
        documentId,
        keyVersion: pendingEntry.keyVersion,
        cacheKey: options.cacheKey,
      });
      Y.applyUpdate(yDoc, decryptedDiff);
    }
    const confirmedBaseState = encodeCanonicalSyncedStateAsUpdate(yDoc);
    return {
      yDoc,
      confirmedBaseState,
      confirmedStateVector: null,
      confirmedSnapshotId: "",
      confirmedSnapshotProofHash: null,
      confirmedSnapshotCiphertextHash: null,
      confirmedClocks: {},
      confirmedVersion: 0,
      keyVersion: created.dekKeyVersion,
      workspaceId: created.workspaceId,
      hasPendingChanges: !!pendingEntry,
    };
  }

  const worker = options.worker ?? getCryptoWorker();
  const kekEntry = requireOfflineDek ? await getOfflineKek(cacheEntry.workspaceId) : null;
  if (kekEntry) {
    await worker.restoreKekFromOffline({
      workspaceId: kekEntry.workspaceId,
      keyVersion: kekEntry.keyVersion,
      isActive: true,
    });
  }
  if (requireOfflineDek) {
    await worker.restoreDekFromOffline({
      documentId,
      keyVersion: dekEntry!.keyVersion,
      isActive: true,
      cacheKey: options.cacheKey,
    });
  }
  const decryptedState = await worker.decryptOfflineCache({
    ciphertext: cacheEntry.encryptedState,
    nonce: cacheEntry.stateNonce,
    documentId,
    keyVersion: cacheEntry.keyVersion,
    cacheKey: options.cacheKey,
  });

  let hasPending = false;
  const confirmedBaseState =
    cacheEntry.encryptedConfirmedState && cacheEntry.confirmedStateNonce
      ? await worker.decryptOfflineCache({
          ciphertext: cacheEntry.encryptedConfirmedState,
          nonce: cacheEntry.confirmedStateNonce,
          documentId,
          keyVersion: cacheEntry.keyVersion,
          cacheKey: options.cacheKey,
        })
      : null;
  const pendingCandidate = includePendingChanges ? await getPendingChanges(documentId) : null;
  const canReplayPending =
    pendingCandidate !== null &&
    shouldReplayCachedPendingChanges(cacheEntry, confirmedBaseState !== null);
  const pendingEntry = canReplayPending ? pendingCandidate : null;
  const yDoc = new Y.Doc();
  Y.applyUpdate(
    yDoc,
    !includePendingChanges && confirmedBaseState ? confirmedBaseState : decryptedState,
  );
  if (pendingEntry) {
    const decryptedDiff = await worker.decryptOfflinePending({
      ciphertext: pendingEntry.encryptedDiff,
      nonce: pendingEntry.diffNonce,
      documentId,
      keyVersion: pendingEntry.keyVersion,
      cacheKey: options.cacheKey,
    });
    Y.applyUpdate(yDoc, decryptedDiff);
    hasPending = true;
  }
  const recoveredConfirmedBaseState = shouldTreatCachedStateAsConfirmedBase(
    cacheEntry,
    confirmedBaseState !== null,
    pendingCandidate !== null,
  )
    ? canonicalizeRecoveredBaseState(confirmedBaseState ?? decryptedState)
    : null;

  return {
    yDoc,
    confirmedBaseState: recoveredConfirmedBaseState,
    confirmedStateVector: cacheEntry.confirmedStateVector,
    confirmedSnapshotId: cacheEntry.confirmedSnapshotId,
    confirmedSnapshotProofHash: cacheEntry.confirmedSnapshotProofHash ?? null,
    confirmedSnapshotCiphertextHash: cacheEntry.confirmedSnapshotCiphertextHash ?? null,
    confirmedClocks: cacheEntry.confirmedClocks,
    confirmedVersion: cacheEntry.confirmedVersion,
    keyVersion: cacheEntry.keyVersion,
    workspaceId: cacheEntry.workspaceId,
    hasPendingChanges: hasPending,
  };
}

function canonicalizeRecoveredBaseState(update: Uint8Array | null): Uint8Array | null {
  if (!update) return null;
  const doc = new Y.Doc();
  try {
    Y.applyUpdate(doc, update, "remote");
    return encodeCanonicalSyncedStateAsUpdate(doc);
  } finally {
    doc.destroy();
  }
}
