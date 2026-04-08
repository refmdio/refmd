import { buildOfflineDocumentCacheAad } from "@/shared/lib/crypto/aad";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import {
  getOfflineDocumentMeta,
  getOfflineKek,
  putOfflineDek,
  putOfflineDocumentMeta,
  putOfflineKek,
} from "@/shared/lib/offline/storage/store";

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

export async function wrapTitleWithDsk(
  documentId: string,
  title: string,
): Promise<{
  encryptedTitle: Uint8Array;
  encryptedTitleNonce: Uint8Array;
}> {
  const worker = getCryptoWorker();
  const titleAad = buildOfflineDocumentCacheAad(documentId, 0);
  const { ciphertext, iv } = await worker.wrapWithDsk({
    plaintext: new TextEncoder().encode(title),
    aad: titleAad,
  });
  return {
    encryptedTitle: new Uint8Array(ciphertext) as Uint8Array<ArrayBuffer>,
    encryptedTitleNonce: new Uint8Array(iv) as Uint8Array<ArrayBuffer>,
  };
}

export async function cacheOfflineTitle(
  documentId: string,
  workspaceId: string,
  title: string,
): Promise<void> {
  try {
    const { encryptedTitle, encryptedTitleNonce } = await wrapTitleWithDsk(documentId, title);
    const existing = await getOfflineDocumentMeta(documentId);
    await putOfflineDocumentMeta({
      documentId,
      workspaceId,
      encryptedTitle,
      encryptedTitleNonce,
      lastAccessedAt: existing?.lastAccessedAt ?? Date.now(),
      cacheSize: existing?.cacheSize ?? 0,
    });
  } catch {
    // Best effort
  }
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
