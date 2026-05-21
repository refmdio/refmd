import { documentsApi, encryptionApi } from "@/shared/api";
import { cryptoWorkerReady, getKekResolverSession } from "@/entities/session";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { resolveActiveKek, resolveKekByVersion } from "@/shared/lib/crypto/kek-resolver";
import { injectDecryptedTitle } from "@/entities/document";
import type { DocumentResponse } from "@/entities/document";
import { getDocumentEvents } from "@/shared/lib/document/manager";

export async function renameDocument(
  doc: DocumentResponse,
  newTitle: string,
  workspaceId: string,
  oldTitle: string,
): Promise<void> {
  if (!cryptoWorkerReady()) {
    throw new Error("Crypto worker not ready");
  }

  const worker = getCryptoWorker();
  await resolveActiveKek(workspaceId, getKekResolverSession());

  const keysResponse = await encryptionApi.getDocumentKeys(doc.id);
  const activeKey = keysResponse.keys.find((k) => k.is_active);
  if (!activeKey) throw new Error("No active DEK found");
  const keyVersion = activeKey.key_version;

  if (activeKey.kek_version) {
    await resolveKekByVersion(workspaceId, activeKey.kek_version, getKekResolverSession());
  }
  await worker.unwrapDek({
    encryptedDek: base64UrlDecode(activeKey.encrypted_dek),
    nonce: base64UrlDecode(activeKey.nonce),
    documentId: doc.id,
    workspaceId,
    keyVersion,
    isActive: true,
    kekVersion: activeKey.kek_version,
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
  getDocumentEvents().notifyDocumentRename(doc.id, oldTitle, newTitle, doc.is_published);
}
