import { documentsApi, encryptionApi } from "@/shared/api";
import { base64UrlDecode, base64UrlEncode, unwrapDek, encryptTitle } from "@/shared/lib/crypto";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
import { authState, deviceState } from "@/shared/lib/auth-state";
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

  const auth = authState();
  const device = deviceState();
  if (!auth?.umk || !auth.identityKeys || !device?.deviceEcdhPrivate) {
    throw new Error("Not authenticated or missing keys");
  }

  const { kek } = await resolveActiveKek(
    workspaceId,
    { user: auth.user, umk: auth.umk, identityKeys: auth.identityKeys },
    { deviceId: device.deviceId, deviceEcdhPrivate: device.deviceEcdhPrivate },
  );

  const keysResponse = await encryptionApi.getDocumentKeys(doc.id);
  const activeKey = keysResponse.keys.find((k) => k.is_active);
  if (!activeKey) throw new Error("No active DEK found");
  const keyVersion = activeKey.key_version;

  const dek = unwrapDek(
    base64UrlDecode(activeKey.encrypted_dek),
    base64UrlDecode(activeKey.nonce),
    kek,
    doc.id,
    workspaceId,
  );

  const { encrypted, nonce } = encryptTitle(newTitle, dek, doc.id, keyVersion);

  await documentsApi.update(doc.id, {
    encrypted_title: base64UrlEncode(encrypted),
    encrypted_title_nonce: base64UrlEncode(nonce),
    encrypted_title_key_version: keyVersion,
  });

  injectDecryptedTitle(doc.id, newTitle, base64UrlEncode(nonce));
}
