import * as Y from "yjs";
import { getKekResolverSession } from "@/entities/session";
import { getDocumentState } from "../../model/document-state/store";
import { ApiError } from "@/shared/api";
import { documentsApi } from "@/shared/api/documents";
import { encryptionApi } from "@/shared/api/encryption";
import { getPopHeaders } from "@/shared/lib/auth/pop";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
import { KekResolutionError } from "@/shared/lib/crypto/kek-resolver-error";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import {
  blockOfflineCreatedSync,
  deleteOfflineCreated,
  getAllOfflineCreated,
  getDocumentCache,
  getPendingChanges,
  type OfflineCreatedDocument,
  type OfflineCreatedSyncBlockReason,
} from "@/shared/lib/offline/storage/store";
import type { SnapshotSaveFailedPayload } from "@/shared/lib/ws/document-payloads";
import {
  joinTemporaryDocument,
  type DocumentChannelCallbacks,
} from "@/shared/lib/ws/phoenix-channel";
import { ensurePhoenixWsToken } from "@/shared/lib/ws/socket";

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

function isOfflineCreatedBlockedReason(value: unknown): value is OfflineCreatedSyncBlockReason {
  return value === "not_a_member" || value === "permission_denied";
}

function resolveOfflineCreatedBlockReason(error: unknown): OfflineCreatedSyncBlockReason | null {
  if (error instanceof KekResolutionError) return "workspace_unavailable";
  const errorWithStatus = getErrorWithStatusBody(error);
  const bodyError = errorWithStatus?.body?.error ?? errorWithStatus?.data?.error;
  if (isOfflineCreatedBlockedReason(bodyError)) return bodyError;
  if (errorWithStatus?.status === 403) return "permission_denied";
  if (errorWithStatus?.status === 404) return "workspace_unavailable";
  return null;
}

export async function syncOfflineCreatedDocuments(workspaceId?: string): Promise<void> {
  const entries = await getAllOfflineCreated();
  const targetEntries = workspaceId
    ? entries.filter((entry) => entry.workspaceId === workspaceId)
    : entries;

  for (const entry of targetEntries) {
    if (entry.syncBlockedReason) continue;
    try {
      await syncSingleDocument(entry);
    } catch (err) {
      const blockedReason = resolveOfflineCreatedBlockReason(err);
      if (blockedReason) {
        await blockOfflineCreatedSync(entry.documentId, blockedReason);
      }
      const message = blockedReason
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
      const { recoverDocumentFromCache } =
        await import("@/shared/lib/offline/cache/manager/recover");
      const recovered = await recoverDocumentFromCache(entry.documentId).catch(() => null);
      let yjsState: Uint8Array | null = null;
      if (recovered) {
        yjsState = Y.encodeStateAsUpdate(recovered.yDoc);
        recovered.yDoc.destroy();
      }
      const { deleteDocumentOfflineData } = await import("@/shared/lib/offline/storage/store");
      await deleteOfflineCreated(entry.documentId);
      await deleteDocumentOfflineData(entry.documentId).catch(() => {});
      const { createDocumentOffline } = await import("./create");
      const newId = await createDocumentOffline(entry.workspaceId, entry.parentId);
      if (yjsState && yjsState.length > 2) {
        const { getDocumentCache: getCache, putDocumentCache } =
          await import("@/shared/lib/offline/storage/store");
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
      const { getOfflineCreated } = await import("@/shared/lib/offline/storage/store");
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
  let disposeChannel: (() => void) | null = null;
  try {
    const liveState = getDocumentState(entry.documentId);
    if (liveState) {
      Y.applyUpdate(yDoc, Y.encodeStateAsUpdate(liveState.yDoc));
    } else {
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
    }

    await ensurePhoenixWsToken("user");
    const popHeaders = await getPopHeaders();
    const { channel, dispose } = await joinTemporaryDocument(
      entry.documentId,
      {
        pop_challenge: popHeaders["X-PoP-Challenge"],
        pop_signature: popHeaders["X-PoP-Signature"],
        mode: "complete",
      },
      makeNoopCallbacks(),
      "user",
    );
    disposeChannel = dispose;

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
      channel.push("snapshot", envelope);
    });

    const confirmedState = Y.encodeStateAsUpdate(yDoc);
    const { ciphertext: cachedCt, nonce: cachedNonce } = await worker.encryptOfflineCache({
      plaintext: confirmedState,
      documentId: entry.documentId,
      keyVersion: entry.dekKeyVersion,
    });
    const { putDocumentCache: putCache, deletePendingChanges: deletePending } =
      await import("@/shared/lib/offline/storage/store");
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
    await deleteOfflineCreated(entry.documentId);
  } finally {
    yDoc.destroy();
    disposeChannel?.();
  }
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
  const { putOfflineCreated } = await import("@/shared/lib/offline/storage/store");
  await putOfflineCreated({
    ...entry,
    kekWrappedDek: encryptedDek,
    kekWrappedDekNonce: nonce,
    kekVersion: kekResult.keyVersion,
  });
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
    onPublicStatusChanged: () => {},
    onUnauthorized: () => {},
    onError: () => {},
    onClose: () => {},
  };
}
