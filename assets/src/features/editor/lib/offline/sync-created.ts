import * as Y from "yjs";
import { getKekResolverSession } from "@/entities/session";
import { acquireDocumentState, getDocumentState } from "../../model/document-state/store";
import { releaseDocumentState } from "../../model/document-state/lifecycle";
import { ApiError } from "@/shared/api";
import { documentsApi } from "@/shared/api/documents";
import { encryptionApi } from "@/shared/api/encryption";
import { buildChannelPopResource, getChannelPopParams } from "@/shared/lib/auth/pop";
import { advanceKeyDirectoryPinWithProof } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { clientWarn } from "@/shared/lib/logger";
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
  strictChannelPayload,
  type DocumentChannelCallbacks,
} from "@/shared/lib/ws/phoenix-channel";
import { ensurePhoenixWsToken } from "@/shared/lib/ws/socket";
import {
  buildDocumentOperationAdmission,
  hashSnapshotOperation,
  prepareDocumentOperationAdmissionAuthority,
} from "../sync/outbound-admission";

interface ErrorWithStatusBody {
  status?: number;
  body?: Record<string, unknown>;
  data?: Record<string, unknown>;
}

const syncingOfflineCreatedDocuments = new Set<string>();

function getErrorWithStatusBody(error: unknown): ErrorWithStatusBody | null {
  if (error instanceof ApiError) {
    return {
      status: error.status,
      body: error.body,
    };
  }
  return typeof error === "object" && error !== null ? (error as ErrorWithStatusBody) : null;
}

function serializeClientError(error: unknown): unknown {
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack,
    };
  }
  return error;
}

function isOfflineCreatedBlockedReason(value: unknown): value is OfflineCreatedSyncBlockReason {
  return value === "not_a_member" || value === "permission_denied";
}

function resolveOfflineCreatedBlockReason(error: unknown): OfflineCreatedSyncBlockReason | null {
  const errorWithStatus = getErrorWithStatusBody(error);
  const bodyError = errorWithStatus?.body?.error ?? errorWithStatus?.data?.error;
  if (isOfflineCreatedBlockedReason(bodyError)) return bodyError;
  if (errorWithStatus?.status === 403) return "permission_denied";
  if (errorWithStatus?.status === 404) return "workspace_unavailable";
  return null;
}

export async function syncOfflineCreatedDocuments(workspaceId?: string): Promise<number> {
  const entries = await getAllOfflineCreated();
  const targetEntries = workspaceId
    ? entries.filter((entry) => entry.workspaceId === workspaceId)
    : entries;

  for (const entry of targetEntries) {
    if (entry.syncBlockedReason) continue;
    if (syncingOfflineCreatedDocuments.has(entry.documentId)) continue;
    syncingOfflineCreatedDocuments.add(entry.documentId);
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
      clientWarn("offline_created_sync_failed", {
        message,
        documentId: entry.documentId,
        error: serializeClientError(err),
      });
      import("@/shared/lib/notice").then(({ Notice }) => new Notice(message)).catch(() => {});
    } finally {
      syncingOfflineCreatedDocuments.delete(entry.documentId);
    }
  }

  const remainingEntries = await getAllOfflineCreated();
  return remainingEntries.filter(
    (entry) => (!workspaceId || entry.workspaceId === workspaceId) && !entry.syncBlockedReason,
  ).length;
}

async function syncSingleDocument(entry: OfflineCreatedDocument): Promise<void> {
  const worker = getCryptoWorker();
  let releaseAdmissionState = false;
  if (await createDocumentRecordIfMissing(entry)) return;

  try {
    await createDocumentKeyIfMissing(entry);
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

  await worker.restoreDekFromOffline({
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
      } else if (entry.encryptedState.length > 0) {
        const decrypted = await worker.decryptOfflineCache({
          ciphertext: entry.encryptedState,
          nonce: entry.stateNonce,
          documentId: entry.documentId,
          keyVersion: entry.dekKeyVersion,
        });
        if (decrypted.length > 0) Y.applyUpdate(yDoc, decrypted);
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
    const joinPayload = { mode: "complete" };
    const popParams = await getChannelPopParams(
      undefined,
      undefined,
      "user",
      undefined,
      buildChannelPopResource(entry.documentId, "user", undefined, joinPayload),
    );
    const { channel, dispose } = await joinTemporaryDocument(
      entry.documentId,
      {
        ...popParams,
        ...joinPayload,
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
    const pubKeys = await worker.getPublicKeys();
    const signingKeyId = pubKeys.deviceSigningKeyId ?? "";
    let admissionState = getDocumentState(entry.documentId);
    if (!admissionState) {
      await acquireDocumentState(entry.documentId, entry.workspaceId);
      releaseAdmissionState = true;
      admissionState = getDocumentState(entry.documentId);
    }
    if (!admissionState) {
      throw new Error("offline_created_document_state_unavailable");
    }
    const admissionAuthority = await prepareDocumentOperationAdmissionAuthority(
      admissionState,
      entry.documentId,
      signingKeyId,
      "document_snapshot_accepted",
      entry.dekKeyVersion,
    );
    const publicData: Record<string, unknown> = {
      docId: entry.documentId,
      snapshotId,
      signingKeyId,
      keyVersion: entry.dekKeyVersion,
      parentSnapshotId: "GENESIS",
      parentProofHash: "GENESIS",
      parentSnapshotUpdateClocks: {},
      ...admissionAuthority.publicDataFields,
    };
    const { signature } = await worker.signDocumentSnapshot({
      ciphertext: ciphertextB64,
      nonce: nonceB64,
      workspaceId: admissionState.workspaceId,
      publicData,
      authorityBoundary: admissionAuthority.authorityBoundary,
    });
    const { admission, keyDirectoryAdvance } = await buildDocumentOperationAdmission({
      documentId: entry.documentId,
      state: admissionState,
      eventType: "document_snapshot_accepted",
      operationHash: hashSnapshotOperation(ciphertext),
      signature,
      keyVersion: entry.dekKeyVersion,
      authority: admissionAuthority,
    });
    const envelope = {
      ciphertext: ciphertextB64,
      nonce: nonceB64,
      signature,
      admission,
      publicData,
    };
    const saved = await new Promise<{ proofChainHash: string; ciphertextHash: string }>(
      (resolve, reject) => {
        let settled = false;
        const settle = (callback: () => void, timeout: ReturnType<typeof setTimeout>): void => {
          if (settled) return;
          settled = true;
          clearTimeout(timeout);
          callback();
        };
        const timeout = setTimeout(() => {
          settle(() => reject(new Error("Snapshot save timeout")), timeout);
        }, 30000);
        channel.on<{ proofChainHash: string; ciphertextHash: string }>(
          "snapshot-saved",
          (payload) => {
            settle(() => resolve(payload), timeout);
          },
        );
        channel.on("snapshot-save-failed", (payload) => {
          settle(
            () =>
              reject(
                new Error(
                  `Snapshot save failed: ${JSON.stringify(payload as unknown as SnapshotSaveFailedPayload)}`,
                ),
              ),
            timeout,
          );
        });
        channel
          .push("snapshot", strictChannelPayload(envelope))
          .receive("ok", (payload) => {
            settle(
              () => resolve(payload as { proofChainHash: string; ciphertextHash: string }),
              timeout,
            );
          })
          .receive("error", (payload) => {
            settle(
              () =>
                reject(
                  new Error(
                    `Snapshot save failed: ${JSON.stringify(payload as unknown as SnapshotSaveFailedPayload)}`,
                  ),
                ),
              timeout,
            );
          })
          .receive("timeout", () => {
            settle(() => reject(new Error("Snapshot save timeout")), timeout);
          });
      },
    );
    if (saved.ciphertextHash !== ciphertextHash) {
      throw new Error("Snapshot save ack ciphertext hash mismatch");
    }
    await deleteOfflineCreated(entry.documentId);
    await persistConfirmedOfflineCreatedState(entry, yDoc, snapshotId, saved, keyDirectoryAdvance);
  } finally {
    yDoc.destroy();
    disposeChannel?.();
    if (releaseAdmissionState) releaseDocumentState(entry.documentId);
  }
}

async function persistConfirmedOfflineCreatedState(
  entry: OfflineCreatedDocument,
  yDoc: Y.Doc,
  snapshotId: string,
  saved: { proofChainHash: string; ciphertextHash: string },
  keyDirectoryAdvance: Awaited<
    ReturnType<typeof buildDocumentOperationAdmission>
  >["keyDirectoryAdvance"],
): Promise<void> {
  try {
    await advanceKeyDirectoryPinWithProof(keyDirectoryAdvance);

    const worker = getCryptoWorker();
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
    const newPin = updatePinFromState(
      existingPin,
      entry.documentId,
      snapshotId,
      saved.proofChainHash,
      saved.ciphertextHash,
      {},
      0,
    );
    await putDocumentStatePin(newPin).catch(() => {});
  } catch (err) {
    clientWarn("offline_created_confirmed_state_persist_failed", {
      documentId: entry.documentId,
      error: serializeClientError(err),
    });
  }
}

async function fetchExistingDocument(
  entry: OfflineCreatedDocument,
): Promise<Awaited<ReturnType<typeof documentsApi.get>> | null> {
  try {
    const document = await documentsApi.get(entry.documentId);
    return document;
  } catch (err) {
    const errorWithStatus = getErrorWithStatusBody(err);
    if (errorWithStatus?.status === 404) {
      return null;
    }
    throw err;
  }
}

async function createDocumentRecordIfMissing(entry: OfflineCreatedDocument): Promise<boolean> {
  const existingDocument = await fetchExistingDocument(entry);
  if (existingDocument) {
    assertOfflineCreatedDocumentMatches(entry, existingDocument);
    if (existingDocument.active_snapshot_id) {
      await deleteOfflineCreated(entry.documentId);
      return true;
    }
    return false;
  }

  try {
    await documentsApi.create({
      workspace_id: entry.workspaceId,
      doc_type: "document",
      id: entry.documentId,
      title: "Untitled",
      ...(entry.parentId ? { parent_id: entry.parentId } : {}),
      encrypted_title: base64UrlEncode(entry.encryptedTitle),
      encrypted_title_nonce: base64UrlEncode(entry.encryptedTitleNonce),
      encrypted_title_key_version: entry.encryptedTitleKeyVersion,
    });
  } catch (err) {
    const errorWithStatus = getErrorWithStatusBody(err);
    if (errorWithStatus?.status === 409) {
      const persistedDocument = await fetchExistingDocument(entry);
      if (persistedDocument) {
        assertOfflineCreatedDocumentMatches(entry, persistedDocument);
        if (persistedDocument.active_snapshot_id) {
          await deleteOfflineCreated(entry.documentId);
          return true;
        }
        return false;
      }
    }
    throw err;
  }
  return false;
}

function assertOfflineCreatedDocumentMatches(
  entry: OfflineCreatedDocument,
  document: Awaited<ReturnType<typeof documentsApi.get>>,
): void {
  if (document.workspace_id !== entry.workspaceId || document.doc_type !== "document") {
    throw new Error("offline_created_document_id_conflict");
  }
}

async function createDocumentKeyIfMissing(entry: OfflineCreatedDocument): Promise<void> {
  try {
    await encryptionApi.createDocumentKey(entry.documentId, {
      encrypted_dek: base64UrlEncode(entry.kekWrappedDek),
      nonce: base64UrlEncode(entry.kekWrappedDekNonce),
      key_version: entry.dekKeyVersion,
      kek_version: entry.kekVersion,
    });
  } catch (err) {
    const errorWithStatus = getErrorWithStatusBody(err);
    if (errorWithStatus?.status === 409) {
      const keys = await encryptionApi.getDocumentKeys(entry.documentId);
      const existing = keys.keys.find((key) => key.key_version === entry.dekKeyVersion);
      if (
        existing &&
        existing.kek_version === entry.kekVersion &&
        existing.encrypted_dek === base64UrlEncode(entry.kekWrappedDek) &&
        existing.nonce === base64UrlEncode(entry.kekWrappedDekNonce)
      ) {
        return;
      }
    }
    throw err;
  }
}

async function handleKekVersionMismatch(entry: OfflineCreatedDocument): Promise<void> {
  const worker = getCryptoWorker();
  await worker.restoreDekFromOffline({
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
