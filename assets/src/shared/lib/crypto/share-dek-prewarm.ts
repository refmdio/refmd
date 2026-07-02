import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import {
  buildWorkspacePinBootstrapHash,
  type WorkspacePinBootstrapEnvelope,
} from "@/shared/lib/key-directory/workspace-pin-bootstrap";

export interface SharedDekPrewarmAccess {
  shareSlug: string;
  shareId: string;
  workspaceId: string;
  workspacePinBootstrapHash?: string | null;
  workspacePinBootstrap?: WorkspacePinBootstrapEnvelope | null;
  workspacePinReady?: Promise<void>;
  encryptedKeyRefs: string[];
  keyVersion: number;
}

export function getSharedDekCacheKey(documentId: string, shareId: string): string {
  return `share:${shareId}:${documentId}`;
}

const pendingShareDekPrewarms = new Map<string, Promise<void>>();

function shareDekPrewarmKey(
  access: SharedDekPrewarmAccess,
  documentId: string,
  keyVersion: number,
): string {
  return [access.shareSlug, access.shareId, documentId, keyVersion].join(":");
}

async function doPrewarmSharedDekForAccess(
  access: SharedDekPrewarmAccess,
  documentId: string,
  keyVersion: number,
): Promise<void> {
  if (!access.workspacePinBootstrapHash || !access.workspacePinBootstrap) {
    throw new Error("workspace_pin_bootstrap_unavailable");
  }
  await access.workspacePinReady;
  if (
    buildWorkspacePinBootstrapHash({
      workspaceId: access.workspaceId,
      bootstrap: access.workspacePinBootstrap,
    }) !== access.workspacePinBootstrapHash
  ) {
    throw new Error("workspace_pin_bootstrap_mismatch");
  }

  const worker = getShareParticipantCryptoWorker(access.shareSlug);
  const cacheKey = getSharedDekCacheKey(documentId, access.shareId);
  if (await worker.hasDek(documentId, keyVersion, cacheKey)) return;
  await worker.unwrapShareDek({
    documentId,
    encryptedKeyRefs: access.encryptedKeyRefs,
    shareSlug: access.shareSlug,
    candidateShareSlugs: [access.shareSlug, access.shareId],
    shareId: access.shareId,
    keyVersion,
    cacheKey,
  });
}

export function prewarmSharedDekForAccess(
  access: SharedDekPrewarmAccess,
  documentId: string,
  keyVersion = access.keyVersion,
): Promise<void> {
  const key = shareDekPrewarmKey(access, documentId, keyVersion);
  const existing = pendingShareDekPrewarms.get(key);
  if (existing) return existing;

  const promise = doPrewarmSharedDekForAccess(access, documentId, keyVersion).finally(() => {
    if (pendingShareDekPrewarms.get(key) === promise) {
      pendingShareDekPrewarms.delete(key);
    }
  });
  pendingShareDekPrewarms.set(key, promise);
  return promise;
}
