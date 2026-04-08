import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { getOfflineKek } from "@/shared/lib/offline/storage/store";

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

  const { putOfflineCreated, putOfflineDek } = await import("@/shared/lib/offline/storage/store");
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
    await import("@/shared/lib/offline/storage/store");
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

  const { wrapTitleWithDsk } = await import("@/shared/lib/offline/cache/manager/keys");
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
