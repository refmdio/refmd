import { documentsApi, encryptionApi, ApiError } from "@/shared/api";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { cryptoWorkerReady } from "@/shared/lib/auth-state";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
import { documentEvents } from "@/shared/lib/document-manager";
import { injectDecryptedTitle } from "@/entities/document";

export async function createDocument(
  workspaceId: string,
  title: string,
  parentId: string | null,
): Promise<string> {
  if (!cryptoWorkerReady()) {
    throw new Error("Crypto worker not ready");
  }

  await resolveActiveKek(workspaceId);

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

  await documentsApi.create({
    id: documentId,
    workspace_id: workspaceId,
    doc_type: "document",
    title: "Untitled",
    encrypted_title: base64UrlEncode(encryptedTitleBytes),
    encrypted_title_nonce: base64UrlEncode(titleNonce),
    encrypted_title_key_version: 1,
    parent_id: parentId,
  });

  const keyBody = {
    key_version: 1,
    kek_version: kekVersion,
    encrypted_dek: base64UrlEncode(encryptedDek),
    nonce: base64UrlEncode(dekNonce),
  };

  const tryCreateKey = async (): Promise<boolean> => {
    try {
      await encryptionApi.createDocumentKey(documentId, keyBody);
      return true;
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) return true;
      return false;
    }
  };

  if (!(await tryCreateKey()) && !(await tryCreateKey())) {
    try {
      const keys = await encryptionApi.getDocumentKeys(documentId);
      if (!keys.keys.some((k) => k.key_version === keyBody.key_version)) {
        await documentsApi.delete(documentId).catch(() => {});
        throw new Error("Failed to persist document encryption key");
      }
    } catch (e) {
      if (e instanceof Error && e.message === "Failed to persist document encryption key") throw e;
      await documentsApi.delete(documentId).catch(() => {});
      throw new Error("Failed to persist document encryption key");
    }
  }

  injectDecryptedTitle(documentId, title, base64UrlEncode(titleNonce));
  documentEvents.notifyDocumentCreate(documentId);

  return documentId;
}
