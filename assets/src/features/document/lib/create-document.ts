import { documentsApi, encryptionApi, ApiError } from "@/shared/api";
import { cryptoWorkerReady, getKekResolverSession } from "@/entities/session";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
import { injectDecryptedTitle } from "@/entities/document";
import { getApp } from "@/shared/lib/app-context";
class DocumentKeyPersistenceError extends Error {
  constructor() {
    super("Failed to persist document encryption key");
    this.name = "DocumentKeyPersistenceError";
  }
}
async function cleanupFailedDocumentCreation(documentId: string): Promise<void> {
  await documentsApi.delete(documentId).catch(() => {
    // Best-effort cleanup. The original key persistence failure is surfaced to the caller.
  });
}
async function ensureDocumentKeyPersisted(documentId: string, keyVersion: number): Promise<void> {
  try {
    const keys = await encryptionApi.getDocumentKeys(documentId);
    if (keys.keys.some((key) => key.key_version === keyVersion)) {
      return;
    }
  } catch {
    // Fall through and report the typed persistence failure below.
  }
  await cleanupFailedDocumentCreation(documentId);
  throw new DocumentKeyPersistenceError();
}
export async function createDocument(
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
    await ensureDocumentKeyPersisted(documentId, keyBody.key_version);
  }
  injectDecryptedTitle(documentId, title, base64UrlEncode(titleNonce));
  getApp().documentEvents.notifyDocumentCreate(documentId);
  return documentId;
}
