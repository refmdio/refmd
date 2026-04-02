import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getKekResolverSession } from "@/entities/session";
import { resolveKekByVersion } from "@/shared/lib/crypto/kek-resolver";
import { encryptionApi } from "@/shared/api/encryption";
import { documentsApi } from "@/shared/api/documents";
import { resolveSigningKey } from "./document-verification";
import { getDocumentState, type DocumentState } from "./document-state-cache";
import { DocumentSyncError } from "./document-sync-error";
import type { SnapshotProofChainEntry, UpdatePayload } from "@/shared/lib/ws/document-payloads";
function createProcessingCancelledError(): Error {
  const error = new Error("document_processing_cancelled");
  error.name = "AbortError";
  return error;
}
function isDocumentProcessingCancelled(documentId: string, state: DocumentState): boolean {
  return getDocumentState(documentId) !== state || (state.refCount <= 0 && !state._headlessSync);
}
export function throwIfDocumentProcessingCancelled(documentId: string, state: DocumentState): void {
  if (isDocumentProcessingCancelled(documentId, state)) {
    throw createProcessingCancelledError();
  }
}
export function createVerificationFailedError(message: string): DocumentSyncError {
  return new DocumentSyncError("verification_failed", message);
}
export function createRollbackAttackError(message: string): DocumentSyncError {
  return new DocumentSyncError("rollback_attack", message);
}
interface DecryptedUpdate {
  decrypted: Uint8Array;
  deviceKey: string;
  clock: number;
}
export async function verifyAndDecryptUpdates(
  updates: UpdatePayload[],
  state: DocumentState,
  documentId: string,
  allowUnknownSigner = false,
): Promise<DecryptedUpdate[]> {
  const results: DecryptedUpdate[] = [];
  for (const update of updates) {
    throwIfDocumentProcessingCancelled(documentId, state);
    const result = await verifyAndDecryptSingleUpdate(
      update,
      state,
      documentId,
      allowUnknownSigner,
    );
    if (result) {
      results.push(result);
    }
  }
  return results;
}
export async function verifyAndDecryptSingleUpdate(
  update: UpdatePayload,
  state: DocumentState,
  documentId: string,
  allowUnknownSigner = false,
): Promise<DecryptedUpdate | null> {
  throwIfDocumentProcessingCancelled(documentId, state);
  const worker = getCryptoWorker();
  // signingPubKey membership confirmation + TOFU
  const keyResult = await resolveSigningKey(update.publicData.signingPubKey, state);
  if (keyResult.status === "key_changed") {
    throw createVerificationFailedError(`TOFU key change: device ${keyResult.warning.deviceId}`);
  }
  if (keyResult.status === "not_found") {
    if (state.rejectedSigningKeys.has(update.publicData.signingPubKey)) {
      throw createVerificationFailedError(
        `Update: rejected signing key (cross-sign failed) ${update.publicData.signingPubKey}`,
      );
    }
    if (!allowUnknownSigner) {
      throw createVerificationFailedError(
        `Update: unknown signing key ${update.publicData.signingPubKey}`,
      );
    }
  }
  // Ed25519 signature verification (skip if signer is unknown former member)
  if (keyResult.status === "found") {
    const valid = await worker.verifyWsSignature({
      prefix: "refmd_update",
      ciphertext: update.ciphertext,
      nonce: update.nonce,
      publicData: update.publicData,
      signature: base64UrlDecode(update.signature),
      signingPubKey: keyResult.key,
    });
    if (!valid) {
      throw createVerificationFailedError("Update signature verification failed");
    }
  }
  // update_hash recomputation and verification
  const recomputedHash = await worker.computeUpdateHash({
    clock: update.publicData.clock,
    device_signing_pub_key: update.publicData.signingPubKey,
    document_id: documentId,
    encrypted_content: update.ciphertext,
    key_version: update.publicData.keyVersion,
    nonce: update.nonce,
    ref_snapshot_id: update.publicData.refSnapshotId,
    timestamp: update.publicData.timestamp,
  });
  if (recomputedHash !== update.publicData.updateHash) {
    throw createVerificationFailedError("Update hash verification failed");
  }
  // Step 2d/4b: refSnapshotId check
  if (
    state.activeSnapshotId !== null &&
    update.publicData.refSnapshotId !== state.activeSnapshotId
  ) {
    throw createVerificationFailedError(
      `Update refSnapshotId mismatch: expected=${state.activeSnapshotId}, got=${update.publicData.refSnapshotId}`,
    );
  }
  // Step 2e/4c: Clock contiguity check
  const deviceKey = update.publicData.signingPubKey;
  const lastClock = state.knownClocks[deviceKey];
  if (lastClock !== undefined) {
    if (update.publicData.clock <= lastClock) {
      return null; // stale or duplicate
    }
    if (update.publicData.clock !== lastClock + 1) {
      // Clock gap: warn instead of fail-close (design: 欠落警告)
      console.warn(
        `[anti-rollback] Clock gap for device ${deviceKey}: expected=${lastClock + 1}, got=${update.publicData.clock}`,
      );
    }
  } else if (update.publicData.clock !== 0) {
    // First clock gap: warn (design: 欠落警告)
    console.warn(
      `[anti-rollback] First clock for device ${deviceKey} expected 0, got=${update.publicData.clock}`,
    );
  }
  // Step 4d: AEAD decryption (before clock commit — failed decrypt must not poison clocks)
  throwIfDocumentProcessingCancelled(documentId, state);
  await ensureDekCached(documentId, state.workspaceId, update.publicData.keyVersion);
  const decrypted = await worker.decryptContent({
    ciphertext: base64UrlDecode(update.ciphertext),
    nonce: base64UrlDecode(update.nonce),
    documentId,
    keyVersion: update.publicData.keyVersion,
  });
  // Advance local keyVersion if remote uses a newer DEK (after rotation by another client)
  if (update.publicData.keyVersion > state.keyVersion) {
    state.keyVersion = update.publicData.keyVersion;
    checkRotationSnapshot(documentId, state);
  }
  // Commit clocks after successful decrypt
  state.knownClocks[deviceKey] = update.publicData.clock;
  state.confirmedClocks[deviceKey] = update.publicData.clock;
  return { decrypted, deviceKey, clock: update.publicData.clock };
}
export async function verifySnapshotProofChain(
  worker: ReturnType<typeof getCryptoWorker>,
  chain: SnapshotProofChainEntry[],
  snapshotParentProof: string,
  pinnedProofHash: string,
  expectedTailSnapshotId: string,
  expectedTailCiphertextHash: string,
): Promise<void> {
  if (chain.length === 0) return;
  // Step 1: Chain head must match pinned proof hash
  if (chain[0]!.parentSnapshotProof !== pinnedProofHash) {
    throw createRollbackAttackError("Snapshot proof chain: head does not match pinned proof hash");
  }
  // Verify chain terminates at the expected snapshot
  const tailEntry = chain[chain.length - 1]!;
  if (tailEntry.snapshotId !== expectedTailSnapshotId) {
    throw createRollbackAttackError(
      `Snapshot proof chain: tail snapshotId ${tailEntry.snapshotId} does not match expected ${expectedTailSnapshotId}`,
    );
  }
  // Verify tail ciphertext hash matches the actual received snapshot
  if (tailEntry.ciphertextHash !== expectedTailCiphertextHash) {
    throw createRollbackAttackError(
      "Snapshot proof chain: tail ciphertextHash does not match received snapshot",
    );
  }
  // Verify tail parentSnapshotProof matches the received snapshot's parentSnapshotProof
  if (tailEntry.parentSnapshotProof !== snapshotParentProof) {
    throw createRollbackAttackError(
      "Snapshot proof chain: tail parentSnapshotProof does not match received snapshot",
    );
  }
  // Steps 2-3: Verify each link in the chain
  for (let i = 0; i < chain.length; i++) {
    const entry = chain[i]!;
    const computedProof = await worker.computeSnapshotProof({
      ciphertextHash: entry.ciphertextHash,
      parentProof: entry.parentSnapshotProof,
      snapshotId: entry.snapshotId,
    });
    if (i + 1 < chain.length) {
      if (computedProof !== chain[i + 1]!.parentSnapshotProof) {
        throw createRollbackAttackError(`Snapshot proof chain: link ${i} proof mismatch`);
      }
    }
  }
}
/**
 * Ensure a DEK for the given keyVersion is cached.
 * If not cached, fetch all DEK versions from server and unwrap the needed one.
 */
export async function ensureDekCached(
  documentId: string,
  workspaceId: string,
  keyVersion: number,
): Promise<void> {
  const worker = getCryptoWorker();
  const hasDek = await worker.hasDek(documentId, keyVersion);
  if (hasDek) return;
  const keysResponse = await encryptionApi.getDocumentKeys(documentId);
  const key = keysResponse.keys.find((k) => k.key_version === keyVersion);
  if (!key) throw new Error(`DEK version ${keyVersion} not found for document ${documentId}`);
  await resolveKekByVersion(workspaceId, key.kek_version, getKekResolverSession());
  await worker.unwrapDek({
    encryptedDek: base64UrlDecode(key.encrypted_dek),
    nonce: base64UrlDecode(key.nonce),
    documentId,
    workspaceId,
    keyVersion: key.key_version,
    isActive: key.is_active,
    kekVersion: key.kek_version,
  });
  // Persist new KEK and DEK to offline cache for offline recovery
  import("@/shared/lib/offline/cache-manager").then(({ cacheKek, cacheDek }) => {
    cacheKek(workspaceId, key.kek_version).catch(() => {});
    cacheDek(documentId, key.key_version).catch(() => {});
  });
}
/**
 * Check if post-rotation snapshot is needed after remote keyVersion advancement.
 * Fires async and sets pendingRotationSnapshot to trigger snapshot on next auto-sync cycle.
 */
export function checkRotationSnapshot(documentId: string, state: DocumentState): void {
  documentsApi
    .get(documentId)
    .then(async (doc) => {
      // Retry deferred DEK rotation (KEK rotation may have completed since init)
      if (doc.needs_dek_rotation && state._retryDekRotation) {
        try {
          await state._retryDekRotation();
        } catch {
          // Best-effort; will retry on next document open
        }
      }
      if (doc.needs_rotation_snapshot && !state.pendingRotationSnapshot) {
        state.pendingRotationSnapshot = true;
        if (state.autoSync) state.autoSync.notifyLocalEdit();
      } else if (!doc.needs_rotation_snapshot && state.pendingRotationSnapshot) {
        state.pendingRotationSnapshot = false;
      }
    })
    .catch(() => {});
}
