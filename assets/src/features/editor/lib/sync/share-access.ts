import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getShareDekEncryptionKey, unwrapShareDek } from "@/shared/lib/crypto/share-dek";
import { sharesApi } from "@/shared/api";
import { normalizeShareVerificationDirectory } from "@/shared/lib/document/share-verification-directory";
import type { DocumentState } from "../../model/document-state/types";
import type { SharedDocumentAccess } from "../../model/document-state/access";
import { getDocumentCryptoWorker } from "./crypto-worker";

export function getSharedDekCacheKey(documentId: string, shareId: string): string {
  return `share:${shareId}:${documentId}`;
}

export function getDocumentDekCacheKey(state: DocumentState, documentId: string): string {
  if (state.access.kind === "share") {
    return getSharedDekCacheKey(documentId, state.access.shareId);
  }

  return documentId;
}

function toSharedDocumentAccess(
  previous: SharedDocumentAccess,
  response: Awaited<ReturnType<typeof sharesApi.getDocumentBootstrap>>,
): SharedDocumentAccess {
  if (!("document_id" in response)) {
    throw new Error("share_bootstrap_required");
  }

  return {
    kind: "share",
    source: previous.source,
    documentToken: previous.documentToken,
    shareId: response.share_id,
    shareSlug: response.share_slug,
    participantPrincipalId: previous.participantPrincipalId,
    participantDisplayName: previous.participantDisplayName,
    participantDeviceId: previous.participantDeviceId,
    participantSigningPublicKey: previous.participantSigningPublicKey,
    participantEncryptionPublicKey: previous.participantEncryptionPublicKey,
    permission: response.permission,
    passwordProtected: response.password_protected,
    workspaceId: response.workspace_id,
    keyVersion: response.key_version,
    encryptedDek: response.encrypted_dek,
    nonce: response.nonce,
    verificationDirectory: normalizeShareVerificationDirectory(response.verification_directory),
  };
}

function toMountedSharedDocumentAccess(
  previous: SharedDocumentAccess,
  response: Awaited<ReturnType<typeof sharesApi.getShareMount>>,
): SharedDocumentAccess {
  if (!response.admission) {
    throw new Error("mounted_share_admission_unavailable");
  }

  return {
    kind: "share",
    source: previous.source,
    documentToken: previous.documentToken,
    mountId: previous.mountId,
    shareId: response.admission.share_id,
    shareSlug: previous.shareSlug,
    participantPrincipalId: previous.participantPrincipalId,
    participantDisplayName: previous.participantDisplayName,
    participantDeviceId: previous.participantDeviceId,
    participantSigningPublicKey: previous.participantSigningPublicKey,
    participantEncryptionPublicKey: previous.participantEncryptionPublicKey,
    permission: response.admission.permission,
    passwordProtected: response.admission.password_protected,
    workspaceId: response.admission.workspace_id,
    keyVersion: response.admission.key_version,
    encryptedDek: response.admission.encrypted_dek,
    nonce: response.admission.nonce,
    verificationDirectory: normalizeShareVerificationDirectory(
      response.admission.verification_directory,
    ),
  };
}

export async function refreshSharedDocumentAccess(
  state: DocumentState,
): Promise<SharedDocumentAccess> {
  if (state.access.kind !== "share") {
    throw new Error("share_access_unavailable");
  }

  const previousAccess = state.access;
  const access = previousAccess.mountId
    ? toMountedSharedDocumentAccess(
        previousAccess,
        await sharesApi.getShareMount(previousAccess.mountId, { documentId: state.documentId }),
      )
    : await (async () => {
        const response = await sharesApi.getDocumentBootstrap(previousAccess.documentToken);
        if ("bootstrap_required" in response && response.bootstrap_required) {
          window.location.replace(`/share/${response.share_slug}`);
          throw new Error("share_bootstrap_required");
        }
        return toSharedDocumentAccess(previousAccess, response);
      })();

  state.access = access;
  state.workspaceId = access.workspaceId;
  state.readOnly = access.permission !== "edit";

  return access;
}

export async function ensureSharedDekCached(
  state: DocumentState,
  documentId: string,
  keyVersion: number,
): Promise<void> {
  if (state.access.kind !== "share") {
    throw new Error("share_access_unavailable");
  }

  const worker = getDocumentCryptoWorker(state);
  const cacheKey = getSharedDekCacheKey(documentId, state.access.shareId);
  if (await worker.hasDek(documentId, keyVersion, cacheKey)) return;

  let access = state.access;
  if (access.keyVersion !== keyVersion) {
    access = await refreshSharedDocumentAccess(state);
  }

  if (access.keyVersion !== keyVersion) {
    throw new Error(`share_dek_version_unavailable:${keyVersion}`);
  }

  // Canonical bootstrap returns the current share DEK material for this document.
  await worker.cacheDek({
    documentId,
    dek: resolveSharedAccessDek(access, documentId),
    keyVersion,
    cacheKey,
  });

  state.dekResolved = true;
  state.keyVersion = Math.max(state.keyVersion, keyVersion);
}

function resolveSharedAccessDek(access: SharedDocumentAccess, documentId: string): Uint8Array {
  if (!access.passwordProtected) {
    return base64UrlDecode(access.encryptedDek);
  }

  const dekEncryptionKey = getShareDekEncryptionKey(access.shareSlug);
  if (!dekEncryptionKey || !access.nonce) {
    throw new Error("share_password_key_unavailable");
  }

  return unwrapShareDek({
    encryptedDek: base64UrlDecode(access.encryptedDek),
    nonce: base64UrlDecode(access.nonce),
    dekEncryptionKey,
    shareId: access.shareId,
    documentId,
  });
}
