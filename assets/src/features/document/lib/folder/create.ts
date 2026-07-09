import { documentsApi, encryptionApi, ApiError } from "@/shared/api";
import { cryptoWorkerReady, getKekResolverSession } from "@/entities/session";
import { injectDecryptedTitle } from "@/entities/document";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { cacheOfflineTitle } from "@/shared/lib/offline/cache/manager/keys";

async function cleanupFailedFolderCreation(documentId: string): Promise<void> {
  await documentsApi.delete(documentId).catch(() => {});
}

export async function createFolder(
  workspaceId: string,
  title: string,
  parentId: string | null,
): Promise<string> {
  if (!cryptoWorkerReady()) {
    throw new Error("Crypto worker not ready");
  }

  await resolveActiveKek(workspaceId, getKekResolverSession());
  const worker = getCryptoWorker();
  const documentId = crypto.randomUUID();
  const {
    encryptedDek,
    nonce: dekNonce,
    keyVersion: kekVersion,
  } = await worker.generateDek(documentId, workspaceId);
  const { encrypted: encryptedTitleBytes, nonce: titleNonce } = await worker.encryptTitle({
    title,
    documentId,
    keyVersion: 1,
  });

  const result = await documentsApi.create({
    id: documentId,
    workspace_id: workspaceId,
    doc_type: "folder",
    encrypted_title: base64UrlEncode(encryptedTitleBytes),
    encrypted_title_nonce: base64UrlEncode(titleNonce),
    encrypted_title_key_version: 1,
    ...(parentId ? { parent_id: parentId } : {}),
  });

  const keyBody = {
    key_version: 1,
    kek_version: kekVersion,
    encrypted_dek: base64UrlEncode(encryptedDek),
    nonce: base64UrlEncode(dekNonce),
  };
  try {
    await encryptionApi.createDocumentKey(documentId, keyBody);
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 409)) {
      await cleanupFailedFolderCreation(documentId);
      throw error;
    }
  }

  injectDecryptedTitle(documentId, title, base64UrlEncode(titleNonce));
  cacheOfflineTitle(documentId, workspaceId, title).catch(() => {});
  return result.id;
}
