import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { getDocumentVerificationCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getKekResolverSession } from "@/entities/session";
import { resolveKekByVersion } from "@/shared/lib/crypto/kek-resolver";
import { encryptionApi } from "@/shared/api/encryption";
import { documentsApi } from "@/shared/api/documents";
import { documentClockKey } from "@/shared/lib/anti-rollback/clock-observations";
import { getKeyDirectoryPin } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { computeSnapshotProofLinkHash } from "@/shared/lib/anti-rollback/snapshot-proof";
import {
  lookupCachedSigningKey,
  resolveSigningKey,
  type ResolveSigningKeyResult,
} from "./inbound-signing-keys";
import { getDocumentState } from "../../model/document-state/store";
import type { DocumentState } from "../../model/document-state/types";
import { DocumentSyncError } from "./error";
import type {
  SnapshotProofChainEntry,
  UpdatePayload,
  WriteSessionPayload,
} from "@/shared/lib/ws/document-payloads";
import { ensureSharedDekCached, getDocumentDekCacheKey } from "./share-access";
import { getDocumentCryptoWorker } from "./crypto-worker";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import {
  documentWriteSessionAuthorityBoundaryForDocument,
  rememberVerifiedDocumentOperationAdmission,
  verifyDocumentWriteSessionNotInvalidated,
  resolveDocumentWriteSessionSigningKeyFromAdmission,
  verifyDocumentOperationAdmissionAncestry,
  verifyDocumentWriteSessionAdmission,
} from "@/shared/lib/document/document-operation-admission";
import { recordSyncPerf } from "./perf";
import { runDocumentOfflineWrite } from "@/shared/lib/crypto/document-key-write-barrier";
import { createAdmissionKeyDirectoryRefresh } from "./admission-key-directory";
import { computeDocumentUpdateHash } from "./update-hash";
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
  startDeferredVerification?: () => Promise<void>;
}

function writeSessionCounterKey(update: UpdatePayload): string {
  return `${update.publicData.writeSessionEventHash}:${update.publicData.signingKeyId}`;
}

export function writeSessionCacheKey(
  publicData: Pick<UpdatePayload["publicData"], "writeSessionEventHash" | "signingKeyId">,
): string {
  return `${publicData.writeSessionEventHash}:${publicData.signingKeyId}`;
}

export function commitWriteSessionCounter(update: UpdatePayload, state: DocumentState): void {
  const key = writeSessionCounterKey(update);
  const counter = update.publicData.writeSessionCounter;
  const lastCounter = state.writeSessionCounters[key];
  if (lastCounter !== undefined && counter <= lastCounter) {
    throw createVerificationFailedError("Write session counter replay detected");
  }
  state.writeSessionCounters[key] = counter;
}

export function resetWriteSessionCountersForSnapshotBaseline(state: DocumentState): void {
  state.writeSessionCounters = {};
}

export async function rememberVerifiedWriteSessionAdmission(params: {
  payload: WriteSessionPayload;
  state: DocumentState;
  documentId: string;
  actorUserId: string;
}): Promise<void> {
  await verifyDocumentWriteSessionNotInvalidated({
    admission: params.payload.admission,
    publicData: params.payload.publicData,
    workspaceId: params.state.workspaceId,
    documentId: params.documentId,
    keyVersion: params.payload.publicData.keyVersion,
  });
  const current = await getCurrentWorkspacePin(params.state);
  params.state.verifiedWriteSessions.set(writeSessionCacheKey(params.payload.publicData), {
    admission: params.payload.admission,
    publicData: { ...params.payload.publicData },
    actorUserId: params.actorUserId,
    maxUpdateCount: writeSessionMaxUpdateCount(params.payload.admission),
    checkedEventHeadSequence: current.eventHeadSequence,
    checkedEventHeadHash: current.eventHeadHash,
  });
}

export async function refreshVerifiedWriteSessions(
  state: DocumentState,
  documentId: string,
): Promise<number> {
  let refreshed = 0;
  for (const [key, cached] of state.verifiedWriteSessions) {
    try {
      await verifyDocumentWriteSessionNotInvalidated({
        admission: cached.admission,
        publicData: cached.publicData,
        workspaceId: state.workspaceId,
        documentId,
        keyVersion: cached.publicData.keyVersion,
      });
      const current = await getCurrentWorkspacePin(state);
      state.verifiedWriteSessions.set(key, {
        ...cached,
        checkedEventHeadSequence: current.eventHeadSequence,
        checkedEventHeadHash: current.eventHeadHash,
      });
      refreshed++;
    } catch {
      state.verifiedWriteSessions.delete(key);
    }
  }
  return refreshed;
}

async function hasVerifiedWriteSessionAdmission(params: {
  update: UpdatePayload;
  state: DocumentState;
  documentId: string;
  actorUserId: string;
}): Promise<boolean> {
  const cached = params.state.verifiedWriteSessions.get(
    writeSessionCacheKey(params.update.publicData),
  );
  if (!cached) return false;
  if (cached.actorUserId !== params.actorUserId) return false;
  if (!writeSessionPublicDataMatches(cached.publicData, params.update.publicData)) return false;
  if (
    !Number.isSafeInteger(params.update.publicData.writeSessionCounter) ||
    params.update.publicData.writeSessionCounter < 1 ||
    params.update.publicData.writeSessionCounter > cached.maxUpdateCount
  ) {
    return false;
  }
  if (params.update.publicData.docId !== params.documentId) return false;
  if (params.update.publicData.minDekVersion > params.update.publicData.keyVersion) return false;

  const current = await getCurrentWorkspacePin(params.state);
  return (
    current.eventHeadSequence === cached.checkedEventHeadSequence &&
    current.eventHeadHash === cached.checkedEventHeadHash
  );
}

function resolveCachedWriteSessionSigningKey(params: {
  update: UpdatePayload;
  state: DocumentState;
  documentId: string;
}): Extract<ResolveSigningKeyResult, { status: "found" }> | null {
  const cached = params.state.verifiedWriteSessions.get(
    writeSessionCacheKey(params.update.publicData),
  );
  if (!cached) return null;
  if (!writeSessionPublicDataMatches(cached.publicData, params.update.publicData)) return null;
  if (
    !Number.isSafeInteger(params.update.publicData.writeSessionCounter) ||
    params.update.publicData.writeSessionCounter < 1 ||
    params.update.publicData.writeSessionCounter > cached.maxUpdateCount
  ) {
    return null;
  }
  if (params.update.publicData.docId !== params.documentId) return null;
  if (params.update.publicData.minDekVersion > params.update.publicData.keyVersion) return null;

  const admittedKey = resolveDocumentWriteSessionSigningKeyFromAdmission({
    admission: cached.admission,
    publicData: params.update.publicData,
  });
  if (!admittedKey || admittedKey.actorUserId !== cached.actorUserId) return null;

  params.state.signingKeys.set(params.update.publicData.signingKeyId, admittedKey.key);
  params.state.signingKeyOwners.set(params.update.publicData.signingKeyId, admittedKey.actorUserId);
  return {
    status: "found",
    key: admittedKey.key,
    ownerId: admittedKey.actorUserId,
  };
}

const WRITE_SESSION_STABLE_PUBLIC_DATA_KEYS = [
  "docId",
  "signingKeyId",
  "ownerKind",
  "ownerId",
  "authorityKind",
  "authorityId",
  "authorityContextKey",
  "authorityScopeId",
  "authorityPermissionVersion",
  "keyCheckpointSequence",
  "keyCheckpointHash",
  "minDekVersion",
  "writeSessionEventHash",
  "writeSessionId",
] as const;

function writeSessionPublicDataMatches(
  session: WriteSessionPayload["publicData"],
  update: UpdatePayload["publicData"],
): boolean {
  for (const key of WRITE_SESSION_STABLE_PUBLIC_DATA_KEYS) {
    if (session[key] !== update[key]) return false;
  }
  return session.keyVersion <= update.keyVersion;
}

function writeSessionMaxUpdateCount(admission: WriteSessionPayload["admission"]): number {
  const event = admission.workspaceKeyDirectoryEvents.find((candidate) => {
    const payload = recordField(candidate, "document_admission_event_invalid").payload;
    return (
      recordField(payload, "document_admission_payload_invalid").event_type ===
      "document_write_session_admitted"
    );
  });
  if (!event) throw new Error("document_admission_event_missing");
  const payload = recordField(event, "document_admission_event_invalid").payload;
  const body = recordField(
    recordField(payload, "document_admission_payload_invalid").body,
    "document_admission_body_invalid",
  );
  const maxUpdateCount = body.max_update_count;
  if (
    typeof maxUpdateCount !== "number" ||
    !Number.isSafeInteger(maxUpdateCount) ||
    maxUpdateCount < 1
  ) {
    throw new Error("max_update_count_invalid");
  }
  return maxUpdateCount;
}

async function getCurrentWorkspacePin(state: DocumentState) {
  const current = await getKeyDirectoryPin("workspace", state.workspaceId);
  if (!current) throw new Error("key_directory_pin_required");
  return current;
}

function recordField(value: unknown, error: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(error);
  }
  return value as Record<string, unknown>;
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
  deferHybridSignatureForCachedWriteSession = false,
): Promise<DecryptedUpdate | null> {
  throwIfDocumentProcessingCancelled(state);
  const verifyStartedAt = performance.now();
  const worker = getDocumentCryptoWorker(state);
  const recordVerifyStep = (step: string) => {
    recordSyncPerf("remote_update_verify_step", {
      documentId,
      updateHash: update.publicData.updateHash,
      step,
      elapsedMs: performance.now() - verifyStartedAt,
    });
  };
  // signingKeyId membership confirmation + TOFU
  let admissionAncestryVerified = false;
  let keyResult: ResolveSigningKeyResult = lookupCachedSigningKey(
    update.publicData.signingKeyId,
    state,
    {
      includeHistorical: includeHistoricalSigners,
    },
  ) ?? { status: "not_found" };
  if (keyResult.status === "not_found") {
    const cachedWriteSessionKey = resolveCachedWriteSessionSigningKey({
      update,
      state,
      documentId,
    });
    if (cachedWriteSessionKey) {
      keyResult = cachedWriteSessionKey;
      recordVerifyStep("signing_key_resolved_from_verified_write_session");
    }
  }
  if (keyResult.status === "not_found") {
    try {
      await verifyDocumentOperationAdmissionAncestry({
        admission: update.admission,
        workspaceId: state.workspaceId,
        refreshKeyDirectory: createAdmissionKeyDirectoryRefresh(state, documentId),
      });
      admissionAncestryVerified = true;
      const admittedKey = resolveDocumentWriteSessionSigningKeyFromAdmission({
        admission: update.admission,
        publicData: update.publicData,
      });
      if (admittedKey) {
        state.signingKeys.set(update.publicData.signingKeyId, admittedKey.key);
        state.signingKeyOwners.set(update.publicData.signingKeyId, admittedKey.actorUserId);
        keyResult = {
          status: "found",
          key: admittedKey.key,
          ownerId: admittedKey.actorUserId,
        };
      }
    } catch (err) {
      throw createVerificationFailedError(
        err instanceof Error ? err.message : "Update admission verification failed",
      );
    }
    recordVerifyStep("admission_ancestry_for_unknown_signer");
  }
  if (keyResult.status === "not_found") {
    keyResult = await resolveSigningKey(update.publicData.signingKeyId, state, {
      includeHistorical: includeHistoricalSigners,
    });
  }
  recordVerifyStep("signing_key_resolved");
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
  let signatureValidPromise: Promise<boolean> | null = null;
  let startDeferredSignatureVerification: (() => Promise<void>) | undefined;
  const verifyHybridSignature = () =>
    verifyDocumentUpdateSignature(
      update,
      (keyResult as Extract<ResolveSigningKeyResult, { status: "found" }>).key,
      (keyResult as Extract<ResolveSigningKeyResult, { status: "found" }>).ownerId,
      state.workspaceId,
    );
  if (keyResult.status === "found") {
    signatureValidPromise = verifyHybridSignature();
  }

  const recomputedHashPromise = Promise.resolve(
    computeDocumentUpdateHash({
      clock: update.publicData.clock,
      signing_key_id: update.publicData.signingKeyId,
      document_id: documentId,
      encrypted_content: update.ciphertext,
      key_version: update.publicData.keyVersion,
      nonce: update.nonce,
      ref_snapshot_id: update.publicData.refSnapshotId,
      timestamp: update.publicData.timestamp,
    }),
  );

  if (signatureValidPromise && !deferHybridSignatureForCachedWriteSession) {
    const valid = await signatureValidPromise;
    if (!valid) {
      throw createVerificationFailedError("Update signature verification failed");
    }
    signatureValidPromise = null;
  }
  recordVerifyStep(signatureValidPromise ? "hybrid_signature_deferred" : "signature_verified");
  // update_hash recomputation and verification
  const recomputedHash = await recomputedHashPromise;
  if (recomputedHash !== update.publicData.updateHash) {
    throw createVerificationFailedError("Update hash verification failed");
  }
  recordVerifyStep("update_hash_verified");
  const pendingVerifiedSession = state.pendingVerifiedWriteSessions.get(
    writeSessionCacheKey(update.publicData),
  );
  if (pendingVerifiedSession) {
    recordVerifyStep("write_session_admission_pending_wait_start");
    await pendingVerifiedSession;
    recordVerifyStep("write_session_admission_pending_ready");
  }
  try {
    const actorUserId = keyResult.status === "found" ? keyResult.ownerId : "";
    const cachedAdmission = await hasVerifiedWriteSessionAdmission({
      update,
      state,
      documentId,
      actorUserId,
    });
    if (cachedAdmission) {
      recordVerifyStep("write_session_admission_cached");
      if (
        !signatureValidPromise &&
        keyResult.status === "found" &&
        deferHybridSignatureForCachedWriteSession
      ) {
        startDeferredSignatureVerification = () =>
          verifyHybridSignature().then((valid) => {
            if (!valid) {
              throw createVerificationFailedError("Update signature verification failed");
            }
          });
      }
      if (signatureValidPromise) {
        startDeferredSignatureVerification = () =>
          signatureValidPromise!.then((valid) => {
            if (!valid) {
              throw createVerificationFailedError("Update signature verification failed");
            }
          });
      }
    } else {
      if (!signatureValidPromise && keyResult.status === "found") {
        signatureValidPromise = verifyHybridSignature();
      }
      if (signatureValidPromise) {
        const valid = await signatureValidPromise;
        signatureValidPromise = null;
        if (!valid) {
          throw createVerificationFailedError("Update signature verification failed");
        }
        recordVerifyStep("signature_verified");
      }
      await verifyDocumentWriteSessionAdmission({
        admission: update.admission,
        publicData: update.publicData,
        workspaceId: state.workspaceId,
        documentId,
        actorUserId,
      });
      recordVerifyStep("write_session_admission_verified");
      if (!admissionAncestryVerified) {
        await verifyDocumentOperationAdmissionAncestry({
          admission: update.admission,
          workspaceId: state.workspaceId,
          refreshKeyDirectory: createAdmissionKeyDirectoryRefresh(state, documentId),
        });
        recordVerifyStep("admission_ancestry_verified");
      }
      await verifyDocumentWriteSessionNotInvalidated({
        admission: update.admission,
        publicData: update.publicData,
        workspaceId: state.workspaceId,
        documentId,
        keyVersion: update.publicData.keyVersion,
      });
      recordVerifyStep("write_session_not_invalidated");
      rememberVerifiedDocumentOperationAdmission({
        admission: update.admission,
        workspaceId: state.workspaceId,
      });
      await rememberVerifiedWriteSessionAdmission({
        payload: { admission: update.admission, publicData: update.publicData },
        state,
        documentId,
        actorUserId,
      });
    }
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
  recordVerifyStep("dek_ready");
  const decrypted = await worker.decryptContent({
    ciphertext: base64UrlDecode(update.ciphertext),
    nonce: base64UrlDecode(update.nonce),
    documentId,
    keyVersion: update.publicData.keyVersion,
    cacheKey: getDocumentDekCacheKey(state, documentId),
  });
  recordVerifyStep("content_decrypted");
  // Advance local keyVersion if remote uses a newer DEK (after rotation by another client)
  if (update.publicData.keyVersion > state.keyVersion) {
    state.keyVersion = update.publicData.keyVersion;
    checkRotationSnapshot(documentId, state);
  }
  // Commit clocks after successful decrypt
  commitWriteSessionCounter(update, state);
  state.knownClocks[deviceKey] = update.publicData.clock;
  state.confirmedClocks[deviceKey] = update.publicData.clock;
  return {
    decrypted,
    deviceKey,
    clock: update.publicData.clock,
    startDeferredVerification: startDeferredSignatureVerification,
  };
}

export async function verifyDocumentUpdateSignature(
  update: UpdatePayload,
  publicKeyMaterial: HybridSigningPublicKeyMaterial,
  actorUserId: string,
  workspaceId: string,
): Promise<boolean> {
  return getDocumentVerificationCryptoWorker(update.publicData.docId).verifyDocumentUpdateSignature(
    {
      publicKeyMaterial,
      signature: update.signature,
      actorUserId,
      workspaceId,
      publicData: update.publicData,
      authorityBoundary: documentWriteSessionAuthorityBoundaryForDocument({
        publicData: update.publicData,
        workspaceId,
        documentId: update.publicData.docId,
      }),
      ciphertext: update.ciphertext,
      nonce: update.nonce,
    },
  );
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

  await runDocumentOfflineWrite(documentId, () =>
    ensureWorkspaceDekCached(documentId, workspaceId, keyVersion),
  );
}

async function ensureWorkspaceDekCached(
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
  void import("@/shared/lib/offline/cache/manager/keys").then(({ cacheKek, cacheDek }) => {
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
      if (doc.needs_dek_rotation || doc.needs_rotation_snapshot) {
        await state._retryDekRotation?.();
        return;
      }
      if (state.pendingRotationSnapshot) {
        state.pendingRotationSnapshot = false;
      }
    })
    .catch(() => {});
}
