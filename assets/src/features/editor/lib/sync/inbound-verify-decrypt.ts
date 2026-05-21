import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getKekResolverSession } from "@/entities/session";
import { resolveKekByVersion } from "@/shared/lib/crypto/kek-resolver";
import { encryptionApi } from "@/shared/api/encryption";
import { documentsApi } from "@/shared/api/documents";
import { documentClockKey } from "@/shared/lib/anti-rollback/clock-observations";
import { computeSnapshotProofLinkHash } from "@/shared/lib/anti-rollback/snapshot-proof";
import { resolveSigningKey } from "./inbound-signing-keys";
import { getDocumentState } from "../../model/document-state/store";
import type { DocumentState } from "../../model/document-state/types";
import { DocumentSyncError } from "./error";
import type { SnapshotProofChainEntry, UpdatePayload } from "@/shared/lib/ws/document-payloads";
import { ensureSharedDekCached, getDocumentDekCacheKey } from "./share-access";
import { getDocumentCryptoWorker } from "./crypto-worker";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import {
  documentOperationAuthorityBoundary,
  verifyDocumentOperationAdmission,
  verifyDocumentOperationAdmissionAncestry,
} from "@/shared/lib/document/document-operation-admission";
function createProcessingCancelledError(): Error {
  const error = new Error("document_processing_cancelled");
  error.name = "AbortError";
  return error;
}
function isDocumentProcessingCancelled(state: DocumentState): boolean {
  return (
    getDocumentState(state.stateKey) !== state || (state.refCount <= 0 && !state._headlessSync)
  );
}
export function throwIfDocumentProcessingCancelled(state: DocumentState): void {
  if (isDocumentProcessingCancelled(state)) {
    throw createProcessingCancelledError();
  }
}
export function createVerificationFailedError(message: string): DocumentSyncError {
  return new DocumentSyncError("verification_failed", message);
}
export function createRollbackAttackError(message: string): DocumentSyncError {
  return new DocumentSyncError("rollback_attack", message);
}
export function createSyncGapError(message: string): DocumentSyncError {
  return new DocumentSyncError("sync_gap", message);
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
  includeHistoricalSigners = false,
): Promise<DecryptedUpdate[]> {
  const results: DecryptedUpdate[] = [];
  for (const update of updates) {
    throwIfDocumentProcessingCancelled(state);
    const result = await verifyAndDecryptSingleUpdate(
      update,
      state,
      documentId,
      allowUnknownSigner,
      includeHistoricalSigners,
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
  includeHistoricalSigners = false,
): Promise<DecryptedUpdate | null> {
  throwIfDocumentProcessingCancelled(state);
  const worker = getDocumentCryptoWorker(state);
  // signingKeyId membership confirmation + TOFU
  const keyResult = await resolveSigningKey(update.publicData.signingKeyId, state, {
    includeHistorical: includeHistoricalSigners,
  });
  if (keyResult.status === "key_changed") {
    throw createVerificationFailedError(`TOFU key change: device ${keyResult.warning.deviceId}`);
  }
  if (keyResult.status === "not_found") {
    if (state.rejectedSigningKeys.has(update.publicData.signingKeyId)) {
      throw createVerificationFailedError(
        `Update: rejected signing key (cross-sign failed) ${update.publicData.signingKeyId}`,
      );
    }
    if (!allowUnknownSigner) {
      throw createVerificationFailedError(
        `Update: unknown signing key ${update.publicData.signingKeyId}`,
      );
    }
  }
  if (!includeHistoricalSigners && state.revokedSigningKeys.has(update.publicData.signingKeyId)) {
    throw createVerificationFailedError(
      `Update: revoked signing key ${update.publicData.signingKeyId}`,
    );
  }
  // Ed25519 signature verification is mandatory when the signing key is known.
  if (keyResult.status === "found") {
    const valid = await verifyDocumentUpdateSignature(
      update,
      keyResult.key,
      keyResult.ownerId,
      state.workspaceId,
    );
    if (!valid) {
      throw createVerificationFailedError("Update signature verification failed");
    }
  }
  // update_hash recomputation and verification
  const recomputedHash = await worker.computeUpdateHash({
    clock: update.publicData.clock,
    signing_key_id: update.publicData.signingKeyId,
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
  try {
    await verifyDocumentOperationAdmission({
      admission: update.admission,
      eventType: "document_update_accepted",
      publicData: update.publicData,
      workspaceId: state.workspaceId,
      documentId,
      operationHash: recomputedHash,
      signature: update.signature,
      actorUserId: keyResult.status === "found" ? keyResult.ownerId : "",
    });
    await verifyDocumentOperationAdmissionAncestry({
      admission: update.admission,
      workspaceId: state.workspaceId,
    });
  } catch (err) {
    throw createVerificationFailedError(
      err instanceof Error ? err.message : "Update admission verification failed",
    );
  }
  const deviceKey = documentClockKey(update.publicData);
  const lastClock = state.knownClocks[deviceKey];
  // Step 2d/4b: refSnapshotId check
  if (
    state.activeSnapshotId !== null &&
    update.publicData.refSnapshotId !== state.activeSnapshotId
  ) {
    throw createSyncGapError(
      `Update refSnapshotId mismatch: expected=${state.activeSnapshotId}, got=${update.publicData.refSnapshotId}`,
    );
  }
  // Step 2e/4c: Clock contiguity check
  if (lastClock !== undefined) {
    if (update.publicData.clock <= lastClock) {
      return null; // stale or duplicate
    }
    if (update.publicData.clock !== lastClock + 1) {
      throw createSyncGapError(
        `Clock gap for device ${deviceKey}: expected=${lastClock + 1}, got=${update.publicData.clock}`,
      );
    }
  } else if (update.publicData.clock !== 0) {
    throw createSyncGapError(
      `First clock for device ${deviceKey}: expected=0, got=${update.publicData.clock}`,
    );
  }
  // Step 4d: AEAD decryption (before clock commit — failed decrypt must not poison clocks)
  throwIfDocumentProcessingCancelled(state);
  await ensureDekCached(documentId, state.workspaceId, update.publicData.keyVersion, state);
  const decrypted = await worker.decryptContent({
    ciphertext: base64UrlDecode(update.ciphertext),
    nonce: base64UrlDecode(update.nonce),
    documentId,
    keyVersion: update.publicData.keyVersion,
    cacheKey: getDocumentDekCacheKey(state, documentId),
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

export async function verifyDocumentUpdateSignature(
  update: UpdatePayload,
  publicKeyMaterial: HybridSigningPublicKeyMaterial,
  actorUserId: string,
  workspaceId: string,
): Promise<boolean> {
  return getCryptoWorker().verifyDocumentUpdateSignature({
    publicKeyMaterial,
    signature: update.signature,
    actorUserId,
    workspaceId,
    publicData: update.publicData,
    authorityBoundary: documentOperationAuthorityBoundary(
      update.admission,
      "document_update_accepted",
    ),
    ciphertext: update.ciphertext,
    nonce: update.nonce,
  });
}
export async function verifySnapshotProofChain(
  chain: SnapshotProofChainEntry[],
  snapshotParentProof: string,
  pinnedProofHash: string,
  expectedTailSnapshotId: string,
  expectedTailCiphertextHash: string,
  expectedTailSnapshotSignatureHash: string,
  expectedTailSnapshotAdmissionEventHash: string,
): Promise<void> {
  if (chain.length === 0) return;
  // Step 1: Chain head must match pinned proof hash
  if (chain[0]!.parent_proof_hash !== pinnedProofHash) {
    throw createRollbackAttackError("Snapshot proof chain: head does not match pinned proof hash");
  }
  // Verify chain terminates at the expected snapshot
  const tailEntry = chain[chain.length - 1]!;
  if (tailEntry.snapshot_id !== expectedTailSnapshotId) {
    throw createRollbackAttackError(
      `Snapshot proof chain: tail snapshot_id ${tailEntry.snapshot_id} does not match expected ${expectedTailSnapshotId}`,
    );
  }
  // Verify tail ciphertext hash matches the actual received snapshot
  if (tailEntry.ciphertext_hash !== expectedTailCiphertextHash) {
    throw createRollbackAttackError(
      "Snapshot proof chain: tail ciphertextHash does not match received snapshot",
    );
  }
  if (tailEntry.snapshot_signature_hash !== expectedTailSnapshotSignatureHash) {
    throw createRollbackAttackError(
      "Snapshot proof chain: tail snapshotSignatureHash does not match received snapshot",
    );
  }
  if (tailEntry.snapshot_admission_event_hash !== expectedTailSnapshotAdmissionEventHash) {
    throw createRollbackAttackError(
      "Snapshot proof chain: tail snapshotAdmissionEventHash does not match received admission event",
    );
  }
  // Verify tail parentProofHash matches the received snapshot's parentProofHash
  if (tailEntry.parent_proof_hash !== snapshotParentProof) {
    throw createRollbackAttackError(
      "Snapshot proof chain: tail parentProofHash does not match received snapshot",
    );
  }
  // Steps 2-3: Verify each link in the chain
  for (let i = 0; i < chain.length; i++) {
    const entry = chain[i]!;
    const computedProof = computeSnapshotProofLinkHash({
      documentId: entry.document_id,
      snapshotId: entry.snapshot_id,
      parentSnapshotId: entry.parent_snapshot_id,
      parentProofHash: entry.parent_proof_hash,
      ciphertextHash: entry.ciphertext_hash,
      snapshotSignatureHash: entry.snapshot_signature_hash,
      snapshotAdmissionEventHash: entry.snapshot_admission_event_hash,
    });
    if (computedProof !== entry.proof_chain_hash) {
      throw createRollbackAttackError(`Snapshot proof chain: link ${i} proof hash mismatch`);
    }
    if (i + 1 < chain.length) {
      if (computedProof !== chain[i + 1]!.parent_proof_hash) {
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
  state?: DocumentState,
): Promise<void> {
  const currentState = state ?? getDocumentState(documentId);
  if (currentState?.access.kind === "share") {
    await ensureSharedDekCached(currentState, documentId, keyVersion);
    return;
  }

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
  import("@/shared/lib/offline/cache/manager/keys").then(({ cacheKek, cacheDek }) => {
    cacheKek(workspaceId, key.kek_version).catch(() => {});
    cacheDek(documentId, key.key_version).catch(() => {});
  });
}
/**
 * Check if post-rotation snapshot is needed after remote keyVersion advancement.
 * Fires async and sets pendingRotationSnapshot to trigger snapshot on next auto-sync cycle.
 */
export function checkRotationSnapshot(documentId: string, state: DocumentState): void {
  if (state.access.kind === "share") return;

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
