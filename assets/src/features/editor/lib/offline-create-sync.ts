import * as Y from "yjs";
import { ApiError } from "@/shared/api";
import { documentsApi } from "@/shared/api/documents";
import { encryptionApi } from "@/shared/api/encryption";
import { getKekResolverSession } from "@/entities/session";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { KekResolutionError } from "@/shared/lib/crypto/kek-resolver-error";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { getPopHeaders } from "@/shared/lib/pop";
import {
  joinDocument,
  leaveDocument,
  pushSnapshot,
  type DocumentChannelCallbacks,
} from "@/shared/lib/ws/phoenix-channel";
import type { SnapshotSaveFailedPayload } from "@/shared/lib/ws/document-payloads";
import {
  deleteOfflineCreated,
  getAllOfflineCreated,
  getDocumentCache,
  getOfflineKek,
  getPendingChanges,
  type OfflineCreatedDocument,
} from "@/shared/lib/offline/offline-store";
interface ErrorWithStatusBody {
  status?: number;
  body?: Record<string, unknown>;
  data?: Record<string, unknown>;
}
function getErrorWithStatusBody(error: unknown): ErrorWithStatusBody | null {
  if (error instanceof ApiError) {
    return {
      status: error.status,
      body: error.body,
    };
  }
  return typeof error === "object" && error !== null ? (error as ErrorWithStatusBody) : null;
}
export async function syncOfflineCreatedDocuments(workspaceId?: string): Promise<void> {
  const entries = await getAllOfflineCreated();
  const targetEntries = workspaceId
    ? entries.filter((entry) => entry.workspaceId === workspaceId)
    : entries;
  for (const entry of targetEntries) {
    try {
      await syncSingleDocument(entry);
    } catch (err) {
      const errorWithStatus = getErrorWithStatusBody(err);
      const isAccessDenied =
        errorWithStatus?.status === 403 ||
        errorWithStatus?.status === 404 ||
        err instanceof KekResolutionError;
      const message = isAccessDenied
        ? "Offline document could not be synced — workspace access may have been revoked. Local copy preserved."
        : "Failed to sync offline document. It will be retried on next connection.";
      console.warn("[offline-create]", message, entry.documentId, err);
      import("@/shared/lib/notice").then(({ Notice }) => new Notice(message)).catch(() => {});
    }
  }
}
async function syncSingleDocument(entry: OfflineCreatedDocument): Promise<void> {
  const worker = getCryptoWorker();
  try {
    await documentsApi.create({
      workspace_id: entry.workspaceId,
      doc_type: "document",
      id: entry.documentId,
      title: "Untitled",
      parent_id: entry.parentId,
      encrypted_title: base64UrlEncode(entry.encryptedTitle),
      encrypted_title_nonce: base64UrlEncode(entry.encryptedTitleNonce),
      encrypted_title_key_version: entry.encryptedTitleKeyVersion,
    });
  } catch (err) {
    const errorWithStatus = getErrorWithStatusBody(err);
    if (errorWithStatus?.status === 409) {
      const { recoverDocumentFromCache } = await import("@/shared/lib/offline/cache-manager");
      const recovered = await recoverDocumentFromCache(entry.documentId).catch(() => null);
      let yjsState: Uint8Array | null = null;
      if (recovered) {
        yjsState = Y.encodeStateAsUpdate(recovered.yDoc);
        recovered.yDoc.destroy();
      }
      const { deleteDocumentOfflineData } = await import("@/shared/lib/offline/offline-store");
      await deleteOfflineCreated(entry.documentId);
      await deleteDocumentOfflineData(entry.documentId).catch(() => {});
      const newId = await createDocumentOffline(entry.workspaceId, entry.parentId);
      if (yjsState && yjsState.length > 2) {
        const { getDocumentCache: getCache, putDocumentCache } =
          await import("@/shared/lib/offline/offline-store");
        const newCache = await getCache(newId);
        if (newCache) {
          const encrypted = await worker.encryptOfflineCache({
            plaintext: yjsState,
            documentId: newId,
            keyVersion: 1,
          });
          newCache.encryptedState = encrypted.ciphertext;
          newCache.stateNonce = encrypted.nonce;
          await putDocumentCache(newCache);
        }
      }
      const { getOfflineCreated } = await import("@/shared/lib/offline/offline-store");
      const newEntry = await getOfflineCreated(newId);
      if (newEntry) await syncSingleDocument(newEntry);
      return;
    }
    throw err;
  }
  try {
    await encryptionApi.createDocumentKey(entry.documentId, {
      encrypted_dek: base64UrlEncode(entry.kekWrappedDek),
      nonce: base64UrlEncode(entry.kekWrappedDekNonce),
      key_version: entry.dekKeyVersion,
      kek_version: entry.kekVersion,
    });
  } catch (err) {
    const errorWithStatus = getErrorWithStatusBody(err);
    if (errorWithStatus?.status === 422) {
      const body = errorWithStatus.body ?? errorWithStatus.data;
      if (body?.error === "kek_version_mismatch") {
        await handleKekVersionMismatch(entry);
      } else {
        throw err;
      }
    } else {
      throw err;
    }
  }
  await worker.unwrapDekFromOffline({
    ciphertext: entry.wrappedDek,
    iv: entry.wrappedDekNonce,
    documentId: entry.documentId,
    keyVersion: entry.dekKeyVersion,
    isActive: true,
  });
  const yDoc = new Y.Doc();
  const cacheEntry = await getDocumentCache(entry.documentId);
  if (cacheEntry) {
    const decrypted = await worker.decryptOfflineCache({
      ciphertext: cacheEntry.encryptedState,
      nonce: cacheEntry.stateNonce,
      documentId: entry.documentId,
      keyVersion: cacheEntry.keyVersion,
    });
    Y.applyUpdate(yDoc, decrypted);
  }
  const pendingEntry = await getPendingChanges(entry.documentId);
  if (pendingEntry) {
    const decrypted = await worker.decryptOfflinePending({
      ciphertext: pendingEntry.encryptedDiff,
      nonce: pendingEntry.diffNonce,
      documentId: entry.documentId,
      keyVersion: pendingEntry.keyVersion,
    });
    Y.applyUpdate(yDoc, decrypted);
  }
  const popHeaders = await getPopHeaders();
  const channel = await joinDocument(
    entry.documentId,
    {
      pop_challenge: popHeaders["X-PoP-Challenge"],
      pop_signature: popHeaders["X-PoP-Signature"],
      mode: "complete",
    },
    makeNoopCallbacks(),
  );
  const yjsState = Y.encodeStateAsUpdateV2(yDoc);
  const snapshotId = crypto.randomUUID();
  const { ciphertext, nonce } = await worker.encryptSnapshot({
    plaintext: yjsState,
    documentId: entry.documentId,
    keyVersion: entry.dekKeyVersion,
  });
  const ciphertextB64 = base64UrlEncode(ciphertext);
  const nonceB64 = base64UrlEncode(nonce);
  const ciphertextHash = base64UrlEncode(await worker.blake3Hash(ciphertext));
  const deviceId = await worker.getDeviceId();
  const pubKeys = await worker.getPublicKeys();
  const signingPubKey = pubKeys.deviceSigningPublic
    ? base64UrlEncode(pubKeys.deviceSigningPublic)
    : "";
  const publicData: Record<string, unknown> = {
    docId: entry.documentId,
    snapshotId,
    deviceId,
    signingPubKey,
    keyVersion: entry.dekKeyVersion,
    parentSnapshotId: null,
    parentSnapshotProof: "",
    parentSnapshotUpdateClocks: {},
  };
  const { signature } = await worker.signWsEnvelope({
    prefix: "refmd_snapshot",
    ciphertext: ciphertextB64,
    nonce: nonceB64,
    publicData,
  });
  const envelope = {
    ciphertext: ciphertextB64,
    nonce: nonceB64,
    signature: base64UrlEncode(signature),
    publicData,
    ciphertextHash,
  };
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Snapshot save timeout")), 30000);
    channel.on("snapshot-saved", () => {
      clearTimeout(timeout);
      resolve();
    });
    channel.on<SnapshotSaveFailedPayload>("snapshot-save-failed", (payload) => {
      clearTimeout(timeout);
      reject(new Error(`Snapshot save failed: ${JSON.stringify(payload)}`));
    });
    pushSnapshot(entry.documentId, envelope);
  });
  const confirmedState = Y.encodeStateAsUpdate(yDoc);
  const { ciphertext: cachedCt, nonce: cachedNonce } = await worker.encryptOfflineCache({
    plaintext: confirmedState,
    documentId: entry.documentId,
    keyVersion: entry.dekKeyVersion,
  });
  const { putDocumentCache: putCache, deletePendingChanges: deletePending } =
    await import("@/shared/lib/offline/offline-store");
  await putCache({
    documentId: entry.documentId,
    workspaceId: entry.workspaceId,
    encryptedState: cachedCt,
    stateNonce: cachedNonce,
    keyVersion: entry.dekKeyVersion,
    confirmedStateVector: Y.encodeStateVector(yDoc),
    confirmedSnapshotId: snapshotId,
    confirmedVersion: 0,
    confirmedClocks: {},
    cachedAt: Date.now(),
    updatedAt: Date.now(),
  });
  await deletePending(entry.documentId).catch(() => {});
  const { getDocumentStatePin, putDocumentStatePin, updatePinFromState } =
    await import("@/shared/lib/anti-rollback/document-state-pins");
  const existingPin = await getDocumentStatePin(entry.documentId).catch(() => null);
  const proofHash = await worker.computeSnapshotProof({
    ciphertextHash,
    parentProof: "",
    snapshotId,
  });
  const newPin = updatePinFromState(
    existingPin,
    entry.documentId,
    snapshotId,
    proofHash,
    ciphertextHash,
    {},
    0,
  );
  await putDocumentStatePin(newPin).catch(() => {});
  yDoc.destroy();
  leaveDocument(entry.documentId);
  await deleteOfflineCreated(entry.documentId);
}
async function handleKekVersionMismatch(entry: OfflineCreatedDocument): Promise<void> {
  const worker = getCryptoWorker();
  await worker.unwrapDekFromOffline({
    ciphertext: entry.wrappedDek,
    iv: entry.wrappedDekNonce,
    documentId: entry.documentId,
    keyVersion: entry.dekKeyVersion,
    isActive: true,
  });
  await resolveActiveKek(entry.workspaceId, getKekResolverSession());
  const { encryptedDek, nonce } = await worker.wrapDek({
    documentId: entry.documentId,
    workspaceId: entry.workspaceId,
  });
  const kekResult = await worker.resolveKek(entry.workspaceId);
  if (!kekResult.found || kekResult.keyVersion === undefined) {
    throw new Error("Failed to resolve new KEK version");
  }
  await encryptionApi.createDocumentKey(entry.documentId, {
    encrypted_dek: base64UrlEncode(encryptedDek),
    nonce: base64UrlEncode(nonce),
    key_version: entry.dekKeyVersion,
    kek_version: kekResult.keyVersion,
  });
  const { putOfflineCreated } = await import("@/shared/lib/offline/offline-store");
  await putOfflineCreated({
    ...entry,
    kekWrappedDek: encryptedDek,
    kekWrappedDekNonce: nonce,
    kekVersion: kekResult.keyVersion,
  });
}
export async function createDocumentOffline(
  workspaceId: string,
  parentId: string | null,
  title?: string,
): Promise<string> {
  const worker = getCryptoWorker();
  const documentTitle = title || "Untitled";
  const kekEntry = await getOfflineKek(workspaceId);
  if (!kekEntry) {
    throw new Error("Cannot create document offline: no KEK cache for workspace");
  }
  await worker.unwrapKekFromOffline({
    ciphertext: kekEntry.wrappedKek,
    iv: kekEntry.wrappedKekNonce,
    workspaceId,
    keyVersion: kekEntry.keyVersion,
    isActive: true,
  });
  const documentId = crypto.randomUUID();
  const dekKeyVersion = 1;
  const { encryptedDek: kekWrappedDek, nonce: kekWrappedDekNonce } = await worker.generateDek(
    documentId,
    workspaceId,
    dekKeyVersion,
    true,
  );
  const { ciphertext: wrappedDek, iv: wrappedDekNonce } = await worker.wrapDekForOffline({
    documentId,
    keyVersion: dekKeyVersion,
  });
  const { encrypted: encryptedTitle, nonce: encryptedTitleNonce } = await worker.encryptTitle({
    title: documentTitle,
    documentId,
    keyVersion: dekKeyVersion,
  });
  const emptyState = new Uint8Array(0);
  const { ciphertext: encryptedState, nonce: stateNonce } = await worker.encryptOfflineCache({
    plaintext: emptyState,
    documentId,
    keyVersion: dekKeyVersion,
  });
  const { putOfflineCreated, putOfflineDek } = await import("@/shared/lib/offline/offline-store");
  await putOfflineDek({
    documentId,
    wrappedDek,
    wrappedDekNonce,
    keyVersion: dekKeyVersion,
    cachedAt: Date.now(),
  });
  await putOfflineCreated({
    documentId,
    workspaceId,
    parentId,
    encryptedTitle,
    encryptedTitleNonce,
    encryptedTitleKeyVersion: dekKeyVersion,
    wrappedDek,
    wrappedDekNonce,
    dekKeyVersion,
    kekWrappedDek,
    kekWrappedDekNonce,
    kekVersion: kekEntry.keyVersion,
    encryptedState,
    stateNonce,
    createdAt: Date.now(),
  });
  const { getOfflineDocumentIndex, putOfflineDocumentIndex, putOfflineDocumentMeta } =
    await import("@/shared/lib/offline/offline-store");
  const existing = await getOfflineDocumentIndex(workspaceId).catch(
    (): Awaited<ReturnType<typeof getOfflineDocumentIndex>> => [],
  );
  existing.push({
    documentId,
    workspaceId,
    parentId,
    position: existing.length,
    docType: "document",
    folderTitle: null,
    archivedAt: null,
    isEncrypted: true,
    updatedAt: new Date().toISOString(),
  });
  await putOfflineDocumentIndex(workspaceId, existing);
  const { wrapTitleWithDsk } = await import("@/shared/lib/offline/cache-manager");
  const wrappedTitle = await wrapTitleWithDsk(documentId, documentTitle);
  await putOfflineDocumentMeta({
    documentId,
    workspaceId,
    encryptedTitle: wrappedTitle.encryptedTitle,
    encryptedTitleNonce: wrappedTitle.encryptedTitleNonce,
    lastAccessedAt: Date.now(),
    cacheSize: 0,
  });
  return documentId;
}
function makeNoopCallbacks(): DocumentChannelCallbacks {
  return {
    onDocument: () => {},
    onUpdate: () => {},
    onSnapshot: () => {},
    onUpdateSaved: () => {},
    onUpdateSaveFailed: () => {},
    onSnapshotSaved: () => {},
    onSnapshotSaveFailed: () => {},
    onEphemeralMessage: () => {},
    onPeerLeft: () => {},
    onUnauthorized: () => {},
    onError: () => {},
    onClose: () => {},
  };
}
