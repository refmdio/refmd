import { registerSessionCleanup } from "@/shared/lib/auth/session-cleanup";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { workspacesApi } from "@/shared/api";
import { installWorkspaceOperationCheckpointPin } from "@/shared/lib/crypto/kek-resolver";
import type { SignedPqWrapRecord } from "@/shared/lib/crypto/signed-pq-wrap";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";

interface ShareAccess {
  url: string;
}

const shareAccessStore = new Map<string, ShareAccess>();

function key(documentId: string, shareId: string): string {
  return `${documentId}:${shareId}`;
}

export async function rememberShareAccess(
  documentId: string,
  shareId: string,
  access: ShareAccess,
): Promise<void> {
  shareAccessStore.set(key(documentId, shareId), access);
  try {
    const worker = getCryptoWorker();
    if (!(await worker.loadStoredDsk())) return;
    await worker.storeShareManagementTokenWithDsk({
      plaintext: new TextEncoder().encode(JSON.stringify(access)),
      documentId,
      shareId,
    });
  } catch {
    // In-memory access remains available for the current tab.
  }
}

export function readShareUrl(documentId: string, shareId: string): string | undefined {
  return shareAccessStore.get(key(documentId, shareId))?.url;
}

export async function restoreShareAccesses(
  documentId: string,
  shareIds: string[],
  options: {
    workspaceId?: string;
    shares?: Array<{
      id: string;
      share_link_secret_backup_wraps?: unknown[] | null;
    }>;
  } = {},
): Promise<void> {
  try {
    const worker = getCryptoWorker();
    if (!(await worker.loadStoredDsk())) return;
    await Promise.all(
      shareIds.map(async (shareId) => {
        const cacheKey = key(documentId, shareId);
        if (shareAccessStore.has(cacheKey)) return;
        const plaintext = await worker.loadShareManagementTokenWithDsk({ documentId, shareId });
        if (!plaintext) return;

        try {
          const access = JSON.parse(new TextDecoder().decode(plaintext)) as ShareAccess;
          if (access.url) {
            shareAccessStore.set(cacheKey, access);
          }
        } catch {
          await worker.deleteShareManagementTokenWithDsk({ documentId, shareId });
        }
      }),
    );
    if (options.workspaceId && options.shares) {
      await restoreShareAccessesFromBackupWraps(documentId, options.workspaceId, options.shares);
    }
  } catch {
    // Best effort only.
  }
}

async function restoreShareAccessesFromBackupWraps(
  documentId: string,
  workspaceId: string,
  shares: Array<{
    id: string;
    share_link_secret_backup_wraps?: unknown[] | null;
  }>,
): Promise<void> {
  const worker = getCryptoWorker();
  const signingMaterialByKey = new Map<string, HybridSigningPublicKeyMaterial>();

  for (const share of shares) {
    const cacheKey = key(documentId, share.id);
    if (shareAccessStore.has(cacheKey)) continue;

    for (const rawWrap of share.share_link_secret_backup_wraps ?? []) {
      const wrap = rawWrap as SignedPqWrapRecord;
      const sender = wrap.sender as Record<string, unknown>;
      const senderUserId = sender.user_id;
      const senderSigningKeyId = sender.signing_key_id;
      if (typeof senderUserId !== "string" || typeof senderSigningKeyId !== "string") continue;

      let senderMaterial = signingMaterialByKey.get(senderSigningKeyId);
      if (!senderMaterial) {
        const devices = await workspacesApi.listMemberDevices(workspaceId, senderUserId, true);
        const senderDevice = devices.devices.find(
          (device) => device.signing_key_id === senderSigningKeyId,
        );
        if (!senderDevice) continue;
        senderMaterial =
          senderDevice.hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial;
        signingMaterialByKey.set(senderSigningKeyId, senderMaterial);
      }

      try {
        const expectedOperationCheckpoint = await installWorkspaceOperationCheckpointPin(
          workspaceId,
          wrap as unknown as Record<string, unknown>,
        );
        const opened = await worker.openSignedPqShareLinkSecretBackupWrap({
          record: wrap,
          senderSigningPublicKeyMaterial: senderMaterial,
          expectedShareId: share.id,
          expectedOperationCheckpoint,
        });
        const url = `${window.location.origin}${opened.sharePathWithFragment}`;
        await rememberShareAccess(documentId, share.id, { url });
        break;
      } catch {
        // Try the next recipient wrap.
      }
    }
  }
}

export function forgetShareAccess(documentId: string, shareId: string): void {
  shareAccessStore.delete(key(documentId, shareId));
  void getCryptoWorker().deleteShareManagementTokenWithDsk({ documentId, shareId });
}

export function clearRememberedShareAccesses(): void {
  shareAccessStore.clear();
}

registerSessionCleanup(clearRememberedShareAccesses);
