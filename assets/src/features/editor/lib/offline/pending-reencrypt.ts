import type { CryptoWorkerClient } from "@/shared/lib/crypto/worker/client";
import {
  getPendingChanges,
  replacePendingChangesIfUnchanged,
} from "@/shared/lib/offline/storage/store";
import { recordSyncPerf } from "../sync/perf";

export async function reencryptPendingChangesForLatestDek(params: {
  documentId: string;
  latestKeyVersion: number;
  worker: CryptoWorkerClient;
  cacheKey?: string;
}): Promise<boolean> {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const pending = await getPendingChanges(params.documentId);
    if (!pending || pending.keyVersion === params.latestKeyVersion) return false;
    if (pending.keyVersion > params.latestKeyVersion) {
      throw new Error("pending_changes_future_dek_version");
    }

    const plaintext = await params.worker.decryptOfflinePending({
      ciphertext: pending.encryptedDiff,
      nonce: pending.diffNonce,
      documentId: params.documentId,
      keyVersion: pending.keyVersion,
      cacheKey: params.cacheKey,
    });

    try {
      const encrypted = await params.worker.encryptOfflinePending({
        plaintext,
        documentId: params.documentId,
        keyVersion: params.latestKeyVersion,
        cacheKey: params.cacheKey,
      });

      const replaced = await replacePendingChangesIfUnchanged(
        { keyVersion: pending.keyVersion, writeId: pending.writeId },
        {
          ...pending,
          encryptedDiff: encrypted.ciphertext,
          diffNonce: encrypted.nonce,
          keyVersion: params.latestKeyVersion,
          writeId: crypto.randomUUID(),
          updatedAt: Date.now(),
        },
      );
      if (replaced) {
        recordSyncPerf("pending_changes_reencrypted", {
          documentId: params.documentId,
          previousKeyVersion: pending.keyVersion,
          latestKeyVersion: params.latestKeyVersion,
        });
        return true;
      }
    } finally {
      plaintext.fill(0);
    }
  }

  throw new Error("pending_changes_reencryption_raced");
}
