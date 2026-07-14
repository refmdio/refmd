import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import {
  getOfflineDocumentMeta,
  getOfflineKek,
  putOfflineDek,
  putOfflineDocumentMeta,
  putOfflineKek,
} from "@/shared/lib/offline/storage/store";
import { clientWarn } from "@/shared/lib/logger";
import { runDocumentOfflineWrite } from "../../../crypto/document-key-write-barrier";

export async function cacheDek(documentId: string, keyVersion: number): Promise<void> {
  await runDocumentOfflineWrite(documentId, async () => {
    try {
      await putOfflineDek({ documentId, keyVersion, cachedAt: Date.now() });
    } catch (err) {
      clientWarn("offline_cache_dek_failed", { documentId, error: err });
    }
  });
}

export async function cacheKek(workspaceId: string, keyVersion: number): Promise<void> {
  try {
    await putOfflineKek({
      workspaceId,
      keyVersion,
      cachedAt: Date.now(),
    });
  } catch (err) {
    clientWarn("offline_cache_kek_failed", { workspaceId, error: err });
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
  const { ciphertext, iv } = await worker.wrapOfflineDocumentTitleWithDsk({
    plaintext: new TextEncoder().encode(title),
    documentId,
    keyVersion: 0,
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
  await runDocumentOfflineWrite(documentId, async () => {
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
  });
}

export async function recoverKekFromCache(workspaceId: string): Promise<boolean> {
  const kekEntry = await getOfflineKek(workspaceId);
  if (!kekEntry) return false;
  const worker = getCryptoWorker();
  await worker.restoreKekFromOffline({
    workspaceId,
    keyVersion: kekEntry.keyVersion,
    isActive: true,
  });
  return true;
}
