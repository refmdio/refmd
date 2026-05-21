import * as Y from "yjs";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import {
  getDocumentCache,
  getOfflineDek,
  getOfflineKek,
  getPendingChanges,
} from "@/shared/lib/offline/storage/store";
import type { RecoveredDocumentState } from "./types";

export async function recoverDocumentFromCache(
  documentId: string,
): Promise<RecoveredDocumentState | null> {
  const dekEntry = await getOfflineDek(documentId);
  if (!dekEntry) return null;

  const cacheEntry = await getDocumentCache(documentId);
  if (!cacheEntry) {
    const { getOfflineCreated } = await import("@/shared/lib/offline/storage/store");
    const created = await getOfflineCreated(documentId);
    if (!created) return null;

    const worker = getCryptoWorker();
    await worker.restoreDekFromOffline({
      documentId,
      keyVersion: dekEntry.keyVersion,
      isActive: true,
    });
    const yDoc = new Y.Doc();
    if (created.encryptedState.length > 0) {
      const decrypted = await worker.decryptOfflineCache({
        ciphertext: created.encryptedState,
        nonce: created.stateNonce,
        documentId,
        keyVersion: created.dekKeyVersion,
      });
      if (decrypted.length > 0) Y.applyUpdate(yDoc, decrypted);
    }
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
    const confirmedBaseState = Y.encodeStateAsUpdate(yDoc);
    return {
      yDoc,
      confirmedBaseState,
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
  const kekEntry = await getOfflineKek(cacheEntry.workspaceId);
  if (kekEntry) {
    await worker.restoreKekFromOffline({
      workspaceId: kekEntry.workspaceId,
      keyVersion: kekEntry.keyVersion,
      isActive: true,
    });
  }
  await worker.restoreDekFromOffline({
    documentId,
    keyVersion: dekEntry.keyVersion,
    isActive: true,
  });
  const decryptedState = await worker.decryptOfflineCache({
    ciphertext: cacheEntry.encryptedState,
    nonce: cacheEntry.stateNonce,
    documentId,
    keyVersion: cacheEntry.keyVersion,
  });
  const yDoc = new Y.Doc();
  Y.applyUpdate(yDoc, decryptedState);

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
