import * as Y from "yjs";
import {
  documentClockKey,
  getNextClockForDevice,
} from "@/shared/lib/anti-rollback/clock-observations";
import { hasCompleteSnapshotPin } from "@/shared/lib/anti-rollback/document-state-pins";
import { computeSnapshotProofLinkHash } from "@/shared/lib/anti-rollback/snapshot-proof";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import {
  documentOperationAuthorityBoundary,
  resolveDocumentOperationSigningKeyFromAdmission,
  verifyDocumentOperationAdmission,
  verifyDocumentOperationAdmissionAncestry,
} from "@/shared/lib/document/document-operation-admission";
import type {
  DocumentPayload,
  RemoteSnapshotPayload,
  UpdatePayload,
} from "@/shared/lib/ws/document-payloads";
import {
  lookupCachedSigningKey,
  resolveSigningKey,
  type ResolveSigningKeyResult,
} from "./inbound-signing-keys";
import type { DocumentState } from "../../model/document-state/types";
import { detectDocumentRollback, persistDocumentRollbackPin } from "./inbound-rollback";
import { isRecoverableSyncGapError } from "./error";
import { getDocumentDekCacheKey } from "./share-access";
import { getLocalSigningKeyId } from "./share-identity";
import { getDocumentCryptoWorker } from "./crypto-worker";
import { rememberDocumentAdmissionCheckpoint } from "./outbound-admission";
import { applyInitialPublicationState, queuePublicationAutoSync } from "./outbound-publication";
import { setDocumentReadOnly } from "../../model/document-state/signals";
import { recordSyncPerf } from "./perf";
import {
  checkRotationSnapshot,
  createRollbackAttackError,
  createSyncGapError,
  createVerificationFailedError,
  ensureDekCached,
  throwIfDocumentProcessingCancelled,
  verifyAndDecryptSingleUpdate,
  verifyAndDecryptUpdates,
  verifySnapshotProofChain,
} from "./inbound-verify-decrypt";

// ── Initial document load ────────────────────────────────────
// Pattern: decrypt all async FIRST, then apply atomically in transact

export async function handleDocumentMessage(
  payload: DocumentPayload,
  state: DocumentState,
  documentId: string,
): Promise<void> {
  throwIfDocumentProcessingCancelled(state);
  applyInitialPublicationState(documentId, state, payload.publicState);
  if (typeof payload.authorityPermissionVersion === "number") {
    state.authorityPermissionVersion = payload.authorityPermissionVersion;
  }
  if (typeof payload.readOnly === "boolean") {
    setDocumentReadOnly(state.stateKey, payload.readOnly);
  }
  const worker = getDocumentCryptoWorker(state);
  const pin = await detectDocumentRollback(payload, state, documentId);

  // Decrypt snapshot before entering the transaction.
  let decryptedSnapshot: Uint8Array | null = null;
  let snapshotMeta: {
    snapshotId: string;
    parentProofHash: string;
    parentSnapshotUpdateClocks: Record<string, number>;
    ciphertextHash: string;
    proofHash: string;
  } | null = null;

  if (payload.snapshot) {
    const snap = payload.snapshot;
    throwIfDocumentProcessingCancelled(state);

    const { keyResult, admissionAncestryVerified } = await resolveSnapshotSigningKey(snap, state, {
      includeHistorical: true,
    });
    if (keyResult.status === "key_changed") {
      throw createVerificationFailedError(`TOFU key change: device ${keyResult.warning.deviceId}`);
    }
    if (
      keyResult.status === "not_found" &&
      state.rejectedSigningKeys.has(snap.publicData.signingKeyId)
    ) {
      throw createVerificationFailedError(
        `Snapshot: rejected signing key (cross-sign failed) ${snap.publicData.signingKeyId}`,
      );
    }
    if (keyResult.status === "not_found") {
      throw createVerificationFailedError(
        `Snapshot: unknown signing key ${snap.publicData.signingKeyId}`,
      );
    }
    // Signature verification is mandatory once the signing key is resolved.
    if (keyResult.status === "found") {
      const valid = await verifyDocumentSnapshotSignature(
        snap,
        keyResult.key,
        keyResult.ownerId,
        worker,
        state.workspaceId,
      );
      if (!valid) {
        throw createVerificationFailedError("Snapshot signature verification failed");
      }
    }
    if (!payload.snapshotAdmissionEventHash) {
      throw createVerificationFailedError("Snapshot admission event hash missing");
    }
    const snapshotProof = await computeReceivedSnapshotProof(
      worker,
      snap,
      payload.snapshotAdmissionEventHash,
    );
    try {
      await verifyDocumentOperationAdmission({
        admission: snap.admission,
        eventType: "document_snapshot_accepted",
        publicData: snap.publicData,
        workspaceId: state.workspaceId,
        documentId,
        operationHash: snapshotProof.ciphertextHash,
        signature: snap.signature,
        actorUserId: keyResult.ownerId,
        expectedAdmissionEventHash: payload.snapshotAdmissionEventHash,
      });
      if (!admissionAncestryVerified) {
        await verifyDocumentOperationAdmissionAncestry({
          admission: snap.admission,
          workspaceId: state.workspaceId,
        });
      }
    } catch (err) {
      throw createVerificationFailedError(
        err instanceof Error ? err.message : "Snapshot admission verification failed",
      );
    }
    if (payload.ciphertextHash && payload.ciphertextHash !== snapshotProof.ciphertextHash) {
      throw createVerificationFailedError("Snapshot ciphertextHash metadata mismatch");
    }
    if (payload.proofChainHash && payload.proofChainHash !== snapshotProof.proofChainHash) {
      throw createVerificationFailedError("Snapshot proofChainHash metadata mismatch");
    }

    // Step 3c: parentProofHash verification via snapshotProofChain
    // Snapshot ID and proof must come from the same baseline.
    const stateAnchor =
      state.activeSnapshotId && state.snapshotProofHash && state.snapshotCiphertextHash
        ? { snapshotId: state.activeSnapshotId, proofHash: state.snapshotProofHash }
        : null;
    const pinAnchor = hasCompleteSnapshotPin(pin)
      ? { snapshotId: pin.latestSnapshotId, proofHash: pin.latestSnapshotProofHash }
      : null;
    const anchor = pinAnchor ?? stateAnchor;
    if (anchor) {
      const snapshotChanged = snap.publicData.snapshotId !== anchor.snapshotId;

      if (snapshotChanged && payload.snapshotProofChain.length === 0) {
        // Fail-closed: pin exists, snapshot changed, but no proof chain.
        throw createRollbackAttackError(
          "Snapshot changed but no proof chain provided (rollback attack)",
        );
      }

      if (snapshotChanged && payload.snapshotProofChain.length > 0) {
        // anchorProofHash IS the computed proof for the anchor snapshot.
        // Chain head's parentProofHash should match this directly.
        await verifySnapshotProofChain(
          payload.snapshotProofChain,
          snap.publicData.parentProofHash,
          anchor.proofHash,
          snap.publicData.snapshotId,
          snapshotProof.ciphertextHash,
          snapshotProof.signatureHash,
          payload.snapshotAdmissionEventHash,
        );
      }
    } else if (payload.snapshotProofChain.length > 0) {
      await verifySnapshotProofChain(
        payload.snapshotProofChain,
        snap.publicData.parentProofHash,
        "GENESIS",
        snap.publicData.snapshotId,
        snapshotProof.ciphertextHash,
        snapshotProof.signatureHash,
        payload.snapshotAdmissionEventHash,
      );
    }

    // Step 3d: AEAD decryption
    throwIfDocumentProcessingCancelled(state);
    await ensureDekCached(documentId, state.workspaceId, snap.publicData.keyVersion, state);
    decryptedSnapshot = await worker.decryptSnapshot({
      ciphertext: base64UrlDecode(snap.ciphertext),
      nonce: base64UrlDecode(snap.nonce),
      documentId,
      keyVersion: snap.publicData.keyVersion,
      cacheKey: getDocumentDekCacheKey(state, documentId),
    });

    snapshotMeta = {
      snapshotId: snap.publicData.snapshotId,
      parentProofHash: snap.publicData.parentProofHash,
      parentSnapshotUpdateClocks: snap.publicData.parentSnapshotUpdateClocks,
      ciphertextHash: snapshotProof.ciphertextHash,
      proofHash: snapshotProof.proofChainHash,
    };
  }

  // Prepare state for update verification without committing to permanent state yet
  const prevActiveSnapshotId = state.activeSnapshotId;
  const prevKnownClocks = { ...state.knownClocks };
  const prevConfirmedClocks = { ...state.confirmedClocks };
  const prevWriteSessionCounters = { ...state.writeSessionCounters };
  const prevSnapshotBaseClocks = { ...state.snapshotBaseClocks };

  if (snapshotMeta) {
    state.activeSnapshotId = snapshotMeta.snapshotId;
    state.snapshotBaseClocks = { ...snapshotMeta.parentSnapshotUpdateClocks };
    state.knownClocks = {};
    state.confirmedClocks = {};
    state._pendingOutOfOrderUpdates = [];
    clearOutOfOrderGapTimeout(state);
  }

  // Verify and decrypt all updates before entering the transaction.
  let decryptedUpdates: Awaited<ReturnType<typeof verifyAndDecryptUpdates>>;
  try {
    decryptedUpdates = await verifyAndDecryptUpdates(
      payload.updates,
      state,
      documentId,
      false,
      true,
    );
  } catch (err) {
    // Rollback temporary state on verification failure
    state.activeSnapshotId = prevActiveSnapshotId;
    state.knownClocks = prevKnownClocks;
    state.confirmedClocks = prevConfirmedClocks;
    state.writeSessionCounters = prevWriteSessionCounters;
    state.snapshotBaseClocks = prevSnapshotBaseClocks;
    throw err;
  }

  // Version regression check BEFORE applying to Y.Doc (fail-closed)
  let effectiveVersion = payload.latestVersion;
  for (const update of payload.updates) {
    if (update.version > effectiveVersion) effectiveVersion = update.version;
  }
  if (state.latestVersion > 0 && effectiveVersion < state.latestVersion) {
    state.activeSnapshotId = prevActiveSnapshotId;
    state.knownClocks = prevKnownClocks;
    state.confirmedClocks = prevConfirmedClocks;
    state.writeSessionCounters = prevWriteSessionCounters;
    state.snapshotBaseClocks = prevSnapshotBaseClocks;
    throw createRollbackAttackError("Version regression detected");
  }

  // Apply atomically inside the transaction without awaits.
  state._applyingRemote = true;
  try {
    state.yDoc.transact(() => {
      if (decryptedSnapshot) {
        Y.applyUpdateV2(state.yDoc, decryptedSnapshot, "remote");
      }
      for (const { decrypted } of decryptedUpdates) {
        Y.applyUpdate(state.yDoc, decrypted, "remote");
      }
    }, "remote");
  } finally {
    state._applyingRemote = false;
  }

  // Commit snapshot metadata after successful verification + application.
  if (snapshotMeta) {
    state.snapshotProofHash = snapshotMeta.proofHash;
    state.snapshotCiphertextHash = snapshotMeta.ciphertextHash;
  }

  // Build lastSavedState from server data only (decoded snapshot + updates, not live Y.Doc).
  // For same-snapshot delta reconnect (snapshot: null, already initialized),
  // preserve existing lastSavedState and update count — only apply delta to Y.Doc.
  const isDeltaSameSnapshot = !payload.snapshot && state.activeSnapshotId !== null;
  if (!isDeltaSameSnapshot) {
    const serverDoc = new Y.Doc();
    if (decryptedSnapshot) {
      Y.applyUpdateV2(serverDoc, decryptedSnapshot, "remote");
    }
    for (const { decrypted } of decryptedUpdates) {
      Y.applyUpdate(serverDoc, decrypted, "remote");
    }
    state.lastSavedState = Y.encodeStateAsUpdate(serverDoc);
    serverDoc.destroy();

    state.snapshotUpdatesCount = payload.updates.length;
  } else {
    // Delta reconnect: update lastSavedState incrementally with delta updates
    if (state.lastSavedState && decryptedUpdates.length > 0) {
      const trackingDoc = new Y.Doc();
      Y.applyUpdate(trackingDoc, state.lastSavedState, "remote");
      for (const { decrypted } of decryptedUpdates) {
        Y.applyUpdate(trackingDoc, decrypted, "remote");
      }
      state.lastSavedState = Y.encodeStateAsUpdate(trackingDoc);
      trackingDoc.destroy();
    }
    state.snapshotUpdatesCount += payload.updates.length;
  }
  state.latestVersion = effectiveVersion;

  // Advance keyVersion to the highest version seen in initial data
  if (payload.snapshot && payload.snapshot.publicData.keyVersion > state.keyVersion) {
    state.keyVersion = payload.snapshot.publicData.keyVersion;
  }
  for (const update of payload.updates) {
    if (update.publicData.keyVersion > state.keyVersion) {
      state.keyVersion = update.publicData.keyVersion;
    }
  }

  // Persist anti-rollback pin
  persistDocumentRollbackPin(documentId, state);
  rememberDocumentAdmissionCheckpoint(state, payload.snapshot);
  for (const update of payload.updates) {
    rememberDocumentAdmissionCheckpoint(state, update);
  }

  state.initialized = true;
  queuePublicationAutoSync(documentId, state);
}

// ── Remote update ────────────────────────────────────────────

export async function handleRemoteUpdate(
  payload: UpdatePayload,
  state: DocumentState,
  documentId: string,
  localDeviceSigningKeyId?: string,
): Promise<void> {
  const receivedAt = performance.now();
  recordSyncPerf("remote_update_received", {
    documentId,
    updateHash: payload.publicData.updateHash,
    version: payload.version,
  });
  if (!state.initialized) {
    state._pendingRemoteEvents.push({ type: "update", payload });
    return;
  }

  // Reject updates from revoked devices on live path
  if (state.revokedSigningKeys.has(payload.publicData.signingKeyId)) {
    throw new Error(`Rejected live update from revoked device ${payload.publicData.signingKeyId}`);
  }

  // Verify and decrypt (single decryption — includes refSnapshotId + TOFU + signature)
  let result: Awaited<ReturnType<typeof verifyAndDecryptSingleUpdate>>;
  try {
    result = await verifyAndDecryptSingleUpdate(payload, state, documentId);
  } catch (err) {
    if (isRecoverableSyncGapError(err)) {
      enqueueOutOfOrderUpdate(state, payload);
      return;
    }
    throw err;
  }
  if (!result) return; // stale/duplicate
  recordSyncPerf("remote_update_verified", {
    documentId,
    updateHash: payload.publicData.updateHash,
    elapsedMs: performance.now() - receivedAt,
  });

  state._applyingRemote = true;
  try {
    Y.applyUpdate(state.yDoc, result.decrypted, "remote");
  } finally {
    state._applyingRemote = false;
  }
  recordSyncPerf("remote_update_applied", {
    documentId,
    updateHash: payload.publicData.updateHash,
    elapsedMs: performance.now() - receivedAt,
  });

  // Update clocks
  state.knownClocks[result.deviceKey] = result.clock;
  state.confirmedClocks[result.deviceKey] = result.clock;

  // Update lastSavedState: reuse decrypted bytes (no re-decryption)
  if (state.lastSavedState) {
    const trackingDoc = new Y.Doc();
    Y.applyUpdate(trackingDoc, state.lastSavedState, "remote");
    Y.applyUpdate(trackingDoc, result.decrypted, "remote");
    state.lastSavedState = Y.encodeStateAsUpdate(trackingDoc);
    trackingDoc.destroy();
  }

  // Invalidate pre-send rollback state since server baseline has advanced

  if (payload.version > state.latestVersion) {
    state.latestVersion = payload.version;
  }
  state.snapshotUpdatesCount++;

  // Persist anti-rollback pin (version update)
  persistDocumentRollbackPin(documentId, state);
  rememberDocumentAdmissionCheckpoint(state, payload);

  // If this update is from our own device, advance localClock
  if (localDeviceSigningKeyId && payload.publicData.signingKeyId === localDeviceSigningKeyId) {
    if (payload.publicData.clock >= state.localClock) {
      state.localClock = payload.publicData.clock + 1;
    }
  }

  await drainOutOfOrderUpdates(state, documentId, localDeviceSigningKeyId);
}

function enqueueOutOfOrderUpdate(state: DocumentState, payload: UpdatePayload): void {
  const exists = state._pendingOutOfOrderUpdates.some(
    (queued) =>
      queued.publicData.refSnapshotId === payload.publicData.refSnapshotId &&
      queued.publicData.signingKeyId === payload.publicData.signingKeyId &&
      queued.publicData.clock === payload.publicData.clock,
  );
  if (!exists) {
    state._pendingOutOfOrderUpdates.push(payload);
  }
  scheduleOutOfOrderGapTimeout(state);
}

function scheduleOutOfOrderGapTimeout(state: DocumentState): void {
  if (state._syncGapTimer) return;
  state._syncGapTimer = setTimeout(() => {
    state._syncGapTimer = null;
    if (state._pendingOutOfOrderUpdates.length === 0) return;

    const first = state._pendingOutOfOrderUpdates[0]!;
    state._onRecoverableSyncGap?.(
      createSyncGapError(
        `Out-of-order update did not resolve: device=${first.publicData.signingKeyId} clock=${first.publicData.clock}`,
      ),
    );
  }, 2_000);
}

function clearOutOfOrderGapTimeout(state: DocumentState): void {
  if (!state._syncGapTimer) return;
  clearTimeout(state._syncGapTimer);
  state._syncGapTimer = null;
}

async function drainOutOfOrderUpdates(
  state: DocumentState,
  documentId: string,
  localDeviceSigningKeyId?: string,
): Promise<void> {
  if (state._drainingOutOfOrderUpdates) return;
  state._drainingOutOfOrderUpdates = true;
  try {
    let progressed = true;
    while (progressed) {
      progressed = false;
      state._pendingOutOfOrderUpdates.sort(
        (a, b) =>
          a.publicData.signingKeyId.localeCompare(b.publicData.signingKeyId) ||
          a.publicData.clock - b.publicData.clock,
      );

      for (let index = 0; index < state._pendingOutOfOrderUpdates.length; index += 1) {
        const queued = state._pendingOutOfOrderUpdates[index]!;
        const queuedClockKey = documentClockKey(queued.publicData);
        const lastClock = state.knownClocks[queuedClockKey];
        const expectedClock = lastClock === undefined ? 0 : lastClock + 1;
        if (
          queued.publicData.refSnapshotId === state.activeSnapshotId &&
          queued.publicData.clock === expectedClock
        ) {
          state._pendingOutOfOrderUpdates.splice(index, 1);
          await handleRemoteUpdate(queued, state, documentId, localDeviceSigningKeyId);
          progressed = true;
          break;
        }
      }
    }
    if (state._pendingOutOfOrderUpdates.length === 0) {
      clearOutOfOrderGapTimeout(state);
    }
  } finally {
    state._drainingOutOfOrderUpdates = false;
  }
}

// ── Remote snapshot ──────────────────────────────────────────

export async function handleRemoteSnapshot(
  payload: RemoteSnapshotPayload,
  state: DocumentState,
  documentId: string,
): Promise<void> {
  if (!state.initialized) {
    state._pendingRemoteEvents.push({ type: "snapshot", payload });
    return;
  }

  if (state.revokedSigningKeys.has(payload.snapshot.publicData.signingKeyId)) {
    throw new Error(
      `Rejected live snapshot from revoked device ${payload.snapshot.publicData.signingKeyId}`,
    );
  }

  const worker = getDocumentCryptoWorker(state);
  const snap = payload.snapshot;
  if (snap.publicData.snapshotId === state.activeSnapshotId) {
    return;
  }

  const { keyResult, admissionAncestryVerified } = await resolveSnapshotSigningKey(snap, state);
  if (keyResult.status === "key_changed") {
    throw createVerificationFailedError(`TOFU key change: device ${keyResult.warning.deviceId}`);
  }
  if (keyResult.status === "not_found") {
    throw createVerificationFailedError(
      `Remote snapshot: unknown signing key ${snap.publicData.signingKeyId}`,
    );
  }

  // Verify parentSnapshotId matches current active snapshot
  if (
    state.activeSnapshotId !== null &&
    snap.publicData.parentSnapshotId !== state.activeSnapshotId
  ) {
    throw createSyncGapError(
      `Remote snapshot: parentSnapshotId mismatch (expected=${state.activeSnapshotId}, got=${snap.publicData.parentSnapshotId})`,
    );
  }

  if (state.activeSnapshotId === null && snap.publicData.parentSnapshotId !== "GENESIS") {
    throw createVerificationFailedError("Remote snapshot: genesis parentSnapshotId invalid");
  }

  // Verify parentProofHash matches the current active snapshot's proof hash.
  // state.snapshotProofHash IS the computed proof for the current active snapshot.
  // The new snapshot's parentProofHash should match it directly.
  if (state.activeSnapshotId !== null && state.snapshotProofHash && state.snapshotCiphertextHash) {
    if (snap.publicData.parentProofHash !== state.snapshotProofHash) {
      throw createVerificationFailedError("Remote snapshot: parentProofHash verification failed");
    }
  }

  const valid = await verifyDocumentSnapshotSignature(
    snap,
    keyResult.key,
    keyResult.ownerId,
    worker,
    state.workspaceId,
  );
  if (!valid) {
    throw createVerificationFailedError("Remote snapshot signature verification failed");
  }

  if (!payload.snapshotAdmissionEventHash) {
    throw createVerificationFailedError("Remote snapshot: admission event hash missing");
  }
  const remoteProof = await computeReceivedSnapshotProof(
    worker,
    snap,
    payload.snapshotAdmissionEventHash,
  );
  const remoteCiphertextHash = remoteProof.ciphertextHash;
  try {
    await verifyDocumentOperationAdmission({
      admission: snap.admission,
      eventType: "document_snapshot_accepted",
      publicData: snap.publicData,
      workspaceId: state.workspaceId,
      documentId,
      operationHash: remoteCiphertextHash,
      signature: snap.signature,
      actorUserId: keyResult.ownerId,
      expectedAdmissionEventHash: payload.snapshotAdmissionEventHash,
    });
    if (!admissionAncestryVerified) {
      await verifyDocumentOperationAdmissionAncestry({
        admission: snap.admission,
        workspaceId: state.workspaceId,
      });
    }
  } catch (err) {
    throw createVerificationFailedError(
      err instanceof Error ? err.message : "Remote snapshot admission verification failed",
    );
  }
  if (
    !payload.proofChainHash ||
    payload.ciphertextHash !== remoteCiphertextHash ||
    payload.proofChainHash !== remoteProof.proofChainHash
  ) {
    throw createVerificationFailedError("Remote snapshot: proof metadata missing or mismatched");
  }

  await ensureDekCached(documentId, state.workspaceId, snap.publicData.keyVersion, state);
  const decrypted = await worker.decryptSnapshot({
    ciphertext: base64UrlDecode(snap.ciphertext),
    nonce: base64UrlDecode(snap.nonce),
    documentId,
    keyVersion: snap.publicData.keyVersion,
    cacheKey: getDocumentDekCacheKey(state, documentId),
  });

  state._applyingRemote = true;
  try {
    Y.applyUpdateV2(state.yDoc, decrypted, "remote");
  } finally {
    state._applyingRemote = false;
  }

  // Advance local keyVersion if remote uses a newer DEK
  if (snap.publicData.keyVersion > state.keyVersion) {
    state.keyVersion = snap.publicData.keyVersion;
    checkRotationSnapshot(documentId, state);
  }

  state.activeSnapshotId = snap.publicData.snapshotId;
  state.snapshotCiphertextHash = remoteCiphertextHash;
  state.snapshotProofHash = payload.proofChainHash;

  state.snapshotBaseClocks = { ...snap.publicData.parentSnapshotUpdateClocks };
  state.knownClocks = {};
  state.confirmedClocks = {};
  state._pendingOutOfOrderUpdates = [];
  state.snapshotUpdatesCount = 0;
  state.localClock = getNextClockForDevice(state.knownClocks, getLocalSigningKeyId(state));

  // Build lastSavedState from server data only (not live Y.Doc which may have local edits)
  const serverDoc = new Y.Doc();
  Y.applyUpdateV2(serverDoc, decrypted, "remote");
  state.lastSavedState = Y.encodeStateAsUpdate(serverDoc);
  serverDoc.destroy();

  // Persist anti-rollback pin
  persistDocumentRollbackPin(documentId, state);
  rememberDocumentAdmissionCheckpoint(state, payload.snapshot);
}

async function resolveSnapshotSigningKey(
  snap: NonNullable<DocumentPayload["snapshot"]>,
  state: DocumentState,
  options: { includeHistorical?: boolean } = {},
): Promise<{ keyResult: ResolveSigningKeyResult; admissionAncestryVerified: boolean }> {
  let admissionAncestryVerified = false;
  let keyResult: ResolveSigningKeyResult = lookupCachedSigningKey(
    snap.publicData.signingKeyId,
    state,
    options,
  ) ?? { status: "not_found" };

  if (keyResult.status === "not_found") {
    try {
      await verifyDocumentOperationAdmissionAncestry({
        admission: snap.admission,
        workspaceId: state.workspaceId,
      });
      admissionAncestryVerified = true;
      const admittedKey = resolveDocumentOperationSigningKeyFromAdmission({
        admission: snap.admission,
        eventType: "document_snapshot_accepted",
        publicData: snap.publicData,
      });
      if (admittedKey) {
        state.signingKeys.set(snap.publicData.signingKeyId, admittedKey.key);
        state.signingKeyOwners.set(snap.publicData.signingKeyId, admittedKey.actorUserId);
        keyResult = {
          status: "found",
          key: admittedKey.key,
          ownerId: admittedKey.actorUserId,
        };
      }
    } catch (err) {
      throw createVerificationFailedError(
        err instanceof Error ? err.message : "Snapshot admission verification failed",
      );
    }
  }

  if (keyResult.status === "not_found") {
    keyResult = await resolveSigningKey(snap.publicData.signingKeyId, state, options);
  }

  return { keyResult, admissionAncestryVerified };
}

async function computeReceivedSnapshotProof(
  worker: ReturnType<typeof getDocumentCryptoWorker>,
  snap: NonNullable<DocumentPayload["snapshot"]>,
  snapshotAdmissionEventHash: string,
): Promise<{ ciphertextHash: string; signatureHash: string; proofChainHash: string }> {
  const ciphertextHash = base64UrlEncode(await worker.blake3Hash(base64UrlDecode(snap.ciphertext)));
  const signatureHash = base64UrlEncode(
    await worker.blake3Hash(canonicalizeStrictBytes(snap.signature as unknown as StrictJsonValue)),
  );
  const proofChainHash = computeSnapshotProofLinkHash({
    documentId: snap.publicData.docId,
    snapshotId: snap.publicData.snapshotId,
    parentSnapshotId: snap.publicData.parentSnapshotId,
    parentProofHash: snap.publicData.parentProofHash,
    ciphertextHash,
    snapshotSignatureHash: signatureHash,
    snapshotAdmissionEventHash,
  });
  return { ciphertextHash, signatureHash, proofChainHash };
}

async function verifyDocumentSnapshotSignature(
  snap: NonNullable<DocumentPayload["snapshot"]>,
  publicKeyMaterial: HybridSigningPublicKeyMaterial,
  actorUserId: string,
  worker: ReturnType<typeof getDocumentCryptoWorker>,
  workspaceId: string,
): Promise<boolean> {
  return worker.verifyDocumentSnapshotSignature({
    publicKeyMaterial,
    signature: snap.signature,
    actorUserId,
    workspaceId,
    publicData: snap.publicData,
    authorityBoundary: documentOperationAuthorityBoundary(
      snap.admission,
      "document_snapshot_accepted",
    ),
    ciphertext: snap.ciphertext,
    nonce: snap.nonce,
  });
}
