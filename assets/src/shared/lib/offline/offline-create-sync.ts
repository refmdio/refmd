import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { documentsApi } from "@/shared/api/documents";
import { encryptionApi } from "@/shared/api/encryption";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
import { getPopHeaders } from "@/shared/lib/pop";
import {
  joinDocument,
  pushSnapshot,
  leaveDocument,
  type DocumentChannelCallbacks,
} from "@/shared/lib/ws/phoenix-channel";
import * as Y from "yjs";
import {
  getAllOfflineCreated,
  deleteOfflineCreated,
  getOfflineKek,
  getDocumentCache,
  getPendingChanges,
  type OfflineCreatedDocument,
} from "./offline-store";

export async function syncOfflineCreatedDocuments(workspaceId?: string): Promise<void> {
  const entries = await getAllOfflineCreated();
  const targetEntries = workspaceId
    ? entries.filter((e) => e.workspaceId === workspaceId)
    : entries;

  for (const entry of targetEntries) {
    try {
      await syncSingleDocument(entry);
    } catch (err: any) {
      const isAccessDenied =
        err?.status === 403 ||
        err?.status === 404 ||
        (err instanceof Error && err.message.includes("KEK"));
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

  // 1. Create document on server
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
  } catch (err: any) {
    if (err?.status === 409) {
      // 409 means the document ID already exists on the server.
      // This is a true UUID collision only on the FIRST attempt.
      // Guard against infinite retry by checking if this is a recursive call.
      // UUID collision (extremely rare): recover full Y.Doc state, create new document
      // with fresh UUID + crypto material, re-encrypt full Y.Doc state, then sync.
      const { recoverDocumentFromCache } = await import("./cache-manager");
      const recovered = await recoverDocumentFromCache(entry.documentId).catch(() => null);
      let yjsState: Uint8Array | null = null;
      if (recovered) {
        yjsState = Y.encodeStateAsUpdate(recovered.yDoc);
        recovered.yDoc.destroy();
      }

      // Clean up old document's offline data
      const { deleteDocumentOfflineData } = await import("./offline-store");
      await deleteOfflineCreated(entry.documentId);
      await deleteDocumentOfflineData(entry.documentId).catch(() => {});
      const newId = await createDocumentOffline(entry.workspaceId, entry.parentId);

      // Re-encrypt full Y.Doc state under new document ID
      if (yjsState && yjsState.length > 2) {
        const { getDocumentCache, putDocumentCache } = await import("./offline-store");
        const newCache = await getDocumentCache(newId);
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

      const { getOfflineCreated } = await import("./offline-store");
      const newEntry = await getOfflineCreated(newId);
      if (newEntry) await syncSingleDocument(newEntry);
      return;
    }
    throw err;
  }

  // 2. Register DEK
  try {
    await encryptionApi.createDocumentKey(entry.documentId, {
      encrypted_dek: base64UrlEncode(entry.kekWrappedDek),
      nonce: base64UrlEncode(entry.kekWrappedDekNonce),
      key_version: entry.dekKeyVersion,
      kek_version: entry.kekVersion,
    });
  } catch (err: any) {
    if (err?.status === 422) {
      const body = err?.body ?? err?.data;
      if (body?.error === "kek_version_mismatch") {
        await handleKekVersionMismatch(entry);
        // Continue to channel join + genesis snapshot below
      } else {
        throw err;
      }
    } else {
      throw err;
    }
  }

  // 3. Recover Y.Doc from offline cache
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

  // 4. Channel join
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

  // 5. Genesis Snapshot: encrypt Y.Doc state, sign, send
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

  // 6. Send genesis snapshot and wait for confirmation
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Snapshot save timeout")), 30_000);

    channel.on("snapshot-saved", () => {
      clearTimeout(timeout);
      resolve();
    });
    channel.on("snapshot-save-failed", (payload: any) => {
      clearTimeout(timeout);
      reject(new Error(`Snapshot save failed: ${JSON.stringify(payload)}`));
    });

    pushSnapshot(entry.documentId, envelope);
  });

  // 7. Update offline cache with confirmed state
  const confirmedState = Y.encodeStateAsUpdate(yDoc);
  const { ciphertext: cachedCt, nonce: cachedNonce } = await worker.encryptOfflineCache({
    plaintext: confirmedState,
    documentId: entry.documentId,
    keyVersion: entry.dekKeyVersion,
  });
  const { putDocumentCache: putCache, deletePendingChanges: delPending } =
    await import("./offline-store");
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
  await delPending(entry.documentId).catch(() => {});

  // Persist anti-rollback pin for the genesis snapshot
  const { putDocumentStatePin, updatePinFromState, getDocumentStatePin } =
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

  // 8. Cleanup
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

  await resolveActiveKek(entry.workspaceId);

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

  // Update persisted offline-created entry with new KEK wrap info
  const { putOfflineCreated } = await import("./offline-store");
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
  const docTitle = title || "Untitled";

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
    title: docTitle,
    documentId,
    keyVersion: dekKeyVersion,
  });

  const emptyState = new Uint8Array(0);
  const { ciphertext: encryptedState, nonce: stateNonce } = await worker.encryptOfflineCache({
    plaintext: emptyState,
    documentId,
    keyVersion: dekKeyVersion,
  });

  const { putOfflineCreated, putOfflineDek } = await import("./offline-store");

  // Write to offline-dek-cache so the normal recovery chain works after restart
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

  // Write to offline-document-index so the sidebar shows the new document
  const { putOfflineDocumentIndex, getOfflineDocumentIndex, putOfflineDocumentMeta } =
    await import("./offline-store");
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

  // Store DSK-encrypted title in offline-documents for offline title display
  const titleAad = (await import("@/shared/lib/crypto/aad")).buildOfflineDocumentCacheAad(
    documentId,
    0,
  );
  const { ciphertext: encTitleBuf, iv: encTitleIv } = await worker.wrapWithDsk({
    plaintext: new TextEncoder().encode(docTitle),
    aad: titleAad,
  });
  await putOfflineDocumentMeta({
    documentId,
    workspaceId,
    encryptedTitle: new Uint8Array(encTitleBuf),
    encryptedTitleNonce: new Uint8Array(encTitleIv),
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
