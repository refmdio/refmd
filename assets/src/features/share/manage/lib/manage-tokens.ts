import { buildShareManageAccessAad } from "@/shared/lib/crypto/aad";
import { registerSessionCleanup } from "@/shared/lib/auth/session-cleanup";
import { deleteDskSecret, loadDsk, loadDskSecret, storeDskSecret } from "@/shared/lib/crypto/dsk";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

interface ShareAccess {
  manageToken: string;
  url: string;
}

const shareAccessStore = new Map<string, ShareAccess>();
const STORAGE_PREFIX = "refmd-share-access:";

function key(documentId: string, shareId: string): string {
  return `${documentId}:${shareId}`;
}

function storageKey(documentId: string, shareId: string): string {
  return `${STORAGE_PREFIX}${documentId}:${shareId}`;
}

function encodeWrapped(wrapped: { ciphertext: ArrayBuffer; iv: ArrayBuffer }): string {
  return JSON.stringify({
    ciphertext: Array.from(new Uint8Array(wrapped.ciphertext)),
    iv: Array.from(new Uint8Array(wrapped.iv)),
  });
}

function decodeWrapped(raw: string): { ciphertext: ArrayBuffer; iv: ArrayBuffer } {
  const parsed = JSON.parse(raw) as { ciphertext: number[]; iv: number[] };
  return {
    ciphertext: new Uint8Array(parsed.ciphertext).buffer,
    iv: new Uint8Array(parsed.iv).buffer,
  };
}

export async function rememberShareAccess(
  documentId: string,
  shareId: string,
  access: ShareAccess,
): Promise<void> {
  shareAccessStore.set(key(documentId, shareId), access);
  try {
    const dsk = await loadDsk();
    if (!dsk) return;

    const worker = getCryptoWorker();
    await worker.setDsk(dsk);
    const wrapped = await worker.wrapWithDsk({
      plaintext: new TextEncoder().encode(JSON.stringify(access)),
      aad: buildShareManageAccessAad(documentId, shareId),
    });
    await storeDskSecret(storageKey(documentId, shareId), encodeWrapped(wrapped));
  } catch {
    // In-memory access remains available for the current tab.
  }
}

export function readShareManageToken(documentId: string, shareId: string): string | undefined {
  return shareAccessStore.get(key(documentId, shareId))?.manageToken;
}

export function readShareUrl(documentId: string, shareId: string): string | undefined {
  return shareAccessStore.get(key(documentId, shareId))?.url;
}

export async function restoreShareAccesses(documentId: string, shareIds: string[]): Promise<void> {
  try {
    const dsk = await loadDsk();
    if (!dsk) return;

    const worker = getCryptoWorker();
    await worker.setDsk(dsk);
    await Promise.all(
      shareIds.map(async (shareId) => {
        const cacheKey = key(documentId, shareId);
        if (shareAccessStore.has(cacheKey)) return;
        const raw = await loadDskSecret<string>(storageKey(documentId, shareId));
        if (!raw) return;

        try {
          const wrapped = decodeWrapped(raw);
          const plaintext = await worker.unwrapWithDsk({
            ciphertext: wrapped.ciphertext,
            iv: wrapped.iv,
            aad: buildShareManageAccessAad(documentId, shareId),
          });
          const access = JSON.parse(new TextDecoder().decode(plaintext)) as ShareAccess;
          if (access.manageToken && access.url) {
            shareAccessStore.set(cacheKey, access);
          }
        } catch {
          await deleteDskSecret(storageKey(documentId, shareId));
        }
      }),
    );
  } catch {
    // Best effort only.
  }
}

export function forgetShareManageToken(documentId: string, shareId: string): void {
  shareAccessStore.delete(key(documentId, shareId));
  void deleteDskSecret(storageKey(documentId, shareId));
}

export function clearRememberedShareAccesses(): void {
  shareAccessStore.clear();
}

registerSessionCleanup(clearRememberedShareAccesses);
