import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getShareDekEncryptionKey, unwrapShareDek } from "@/shared/lib/crypto/share-dek";
import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";

export interface ShareTitlePayload {
  id?: string;
  document_id?: string;
  share_id: string;
  title: string | null;
  encrypted_title: string | null;
  encrypted_title_nonce: string | null;
  encrypted_title_key_version: number | null;
  encrypted_dek: string;
  nonce: string | null;
  key_version: number;
  doc_type?: "document" | "folder";
  share_slug?: string;
}

interface ResolveShareTitleOptions {
  passwordProtected: boolean;
  passwordKey?: string | null;
  fallback?: string;
}

function payloadDocumentId(payload: ShareTitlePayload): string {
  return payload.document_id ?? payload.id ?? "";
}

function fallbackTitle(payload: ShareTitlePayload, fallback?: string): string {
  if (payload.title) return payload.title;
  if (fallback) return fallback;
  return payload.doc_type === "folder" ? "Shared folder" : "Shared document";
}

function resolveShareDek(
  payload: ShareTitlePayload,
  options: ResolveShareTitleOptions,
): Uint8Array {
  if (!options.passwordProtected) {
    return base64UrlDecode(payload.encrypted_dek);
  }

  const passwordKey = options.passwordKey ?? payload.share_slug;
  const dekEncryptionKey = passwordKey ? getShareDekEncryptionKey(passwordKey) : null;
  if (!dekEncryptionKey || !payload.nonce) {
    throw new Error("share_password_key_unavailable");
  }

  return unwrapShareDek({
    encryptedDek: base64UrlDecode(payload.encrypted_dek),
    nonce: base64UrlDecode(payload.nonce),
    dekEncryptionKey,
    shareId: payload.share_id,
    documentId: payloadDocumentId(payload),
  });
}

export async function resolveShareTitle(
  payload: ShareTitlePayload,
  options: ResolveShareTitleOptions,
): Promise<string> {
  const documentId = payloadDocumentId(payload);
  if (
    documentId &&
    payload.encrypted_title &&
    payload.encrypted_title_nonce &&
    payload.encrypted_title_key_version != null &&
    payload.encrypted_title_key_version === payload.key_version
  ) {
    const worker = getShareParticipantCryptoWorker(
      options.passwordKey ?? payload.share_slug ?? payload.share_id,
    );
    const cacheKey = `share:${payload.share_id}:${documentId}`;

    try {
      const dek = resolveShareDek(payload, options);

      if (!(await worker.hasDek(documentId, payload.key_version, cacheKey))) {
        await worker.cacheDek({
          documentId,
          dek,
          keyVersion: payload.key_version,
          cacheKey,
        });
      }

      return await worker.decryptTitle({
        documentId,
        encrypted: base64UrlDecode(payload.encrypted_title),
        nonce: base64UrlDecode(payload.encrypted_title_nonce),
        keyVersion: payload.encrypted_title_key_version,
        cacheKey,
      });
    } catch {
      // Fall through to the server fallback title.
    }
  }

  return fallbackTitle(payload, options.fallback);
}
