import { documentsApi, encryptionApi } from "@/shared/api";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { cryptoWorkerReady } from "@/shared/lib/auth-state";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
import { injectDecryptedTitle } from "@/entities/document";
import type { DocumentResponse } from "@/entities/document";

export async function renameDocument(
  doc: DocumentResponse,
  newTitle: string,
  workspaceId: string,
): Promise<void> {
  if (doc.doc_type === "folder") {
    await documentsApi.update(doc.id, { title: newTitle });
    return;
  }

  if (!cryptoWorkerReady()) {
    throw new Error("Crypto worker not ready");
  }

  const worker = getCryptoWorker();
  await resolveActiveKek(workspaceId);

  const keysResponse = await encryptionApi.getDocumentKeys(doc.id);
  const activeKey = keysResponse.keys.find((k) => k.is_active);
  if (!activeKey) throw new Error("No active DEK found");
  const keyVersion = activeKey.key_version;

  await worker.unwrapDek({
    encryptedDek: base64UrlDecode(activeKey.encrypted_dek),
    nonce: base64UrlDecode(activeKey.nonce),
    documentId: doc.id,
    workspaceId,
    keyVersion,
  });

  const { encrypted, nonce } = await worker.encryptTitle({
    title: newTitle,
    documentId: doc.id,
    keyVersion,
  });

  await documentsApi.update(doc.id, {
    encrypted_title: base64UrlEncode(encrypted),
    encrypted_title_nonce: base64UrlEncode(nonce),
    encrypted_title_key_version: keyVersion,
  });

  injectDecryptedTitle(doc.id, newTitle, base64UrlEncode(nonce));
}
