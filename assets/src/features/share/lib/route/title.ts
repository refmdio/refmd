import { readCachedDecryptedTitle } from "@/entities/document";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import type { WorkspacePinBootstrapEnvelope } from "@/shared/lib/key-directory/workspace-pin-bootstrap";

export interface ShareTitlePayload {
  id?: string;
  document_id?: string;
  share_id: string;
  encrypted_title: string | null;
  encrypted_title_nonce: string | null;
  encrypted_title_key_version: number | null;
  encrypted_key_refs: string[];
  key_version: number;
  doc_type?: "document" | "folder";
  share_slug?: string;
}

interface ResolveShareTitleOptions {
  passwordProtected: boolean;
  passwordKey?: string | null;
  fallback?: string;
  workspaceId?: string | null;
  workspacePinBootstrapHash?: string | null;
  workspacePinBootstrap?: WorkspacePinBootstrapEnvelope | null;
  allowDekUnwrap?: boolean;
}

function payloadDocumentId(payload: ShareTitlePayload): string {
  return payload.document_id ?? payload.id ?? "";
}

function fallbackTitle(payload: ShareTitlePayload, fallback?: string): string {
  const cachedTitle = readCachedDecryptedTitle(payloadDocumentId(payload));
  if (cachedTitle) return cachedTitle;
  if (fallback) return fallback;
  return payload.doc_type === "folder" ? "Shared folder" : "Shared document";
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
    payload.encrypted_title_key_version != null
  ) {
    if (options.allowDekUnwrap === false) {
      return fallbackTitle(payload, options.fallback);
    }
    const titleKeyVersion = payload.encrypted_title_key_version;
    const worker = getShareParticipantCryptoWorker(
      options.passwordKey ?? payload.share_slug ?? payload.share_id,
    );
    const cacheKey = `share:${payload.share_id}:${documentId}`;
    const candidateShareSlugs = [options.passwordKey, payload.share_slug, payload.share_id].filter(
      (value): value is string => typeof value === "string" && value.length > 0,
    );

    try {
      if (!(await worker.hasDek(documentId, titleKeyVersion, cacheKey))) {
        await worker.unwrapShareDek({
          documentId,
          encryptedKeyRefs: payload.encrypted_key_refs,
          candidateShareSlugs,
          shareId: payload.share_id,
          keyVersion: titleKeyVersion,
          cacheKey,
        });
      }

      return await worker.decryptTitle({
        documentId,
        encrypted: base64UrlDecode(payload.encrypted_title),
        nonce: base64UrlDecode(payload.encrypted_title_nonce),
        keyVersion: titleKeyVersion,
        cacheKey,
      });
    } catch {
      return fallbackTitle(payload, options.fallback);
    }
  }

  return fallbackTitle(payload, options.fallback);
}
