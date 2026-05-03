import * as Y from "yjs";
import { deviceState } from "@/entities/session";
import { getNextClockForDevice } from "@/shared/lib/anti-rollback/clock-observations";
import { hasCompleteSnapshotPin } from "@/shared/lib/anti-rollback/document-state-pins";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import type {
  DocumentPayload,
  RemoteSnapshotPayload,
  UpdatePayload,
} from "@/shared/lib/ws/document-payloads";
import { resolveSigningKey } from "./signing-keys";
import type { DocumentState } from "../../../model/document-state/types";
import { detectDocumentRollback, persistDocumentRollbackPin } from "./rollback";
import { isRecoverableSyncGapError } from "../error";
import { getDocumentDekCacheKey } from "../share-access";
import { getLocalSigningPubKeyB64, getLocalSigningPublicKeyBytes } from "../share-identity";
import { getDocumentCryptoWorker } from "../crypto-worker";
import { applyInitialPublicationState, queuePublicationAutoSync } from "../outbound/publication";
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
} from "./verify-decrypt";

// ── Initial document load ────────────────────────────────────
// Pattern: decrypt all async FIRST, then apply atomically in transact

export async function handleDocumentMessage(
  payload: DocumentPayload,
  state: DocumentState,
  documentId: string,
): Promise<void> {
  throwIfDocumentProcessingCancelled(state);
  applyInitialPublicationState(documentId, state, payload.publicState);
  const worker = getDocumentCryptoWorker(state);
  const pin = await detectDocumentRollback(payload, state, documentId);

  // Phase 1: Decrypt snapshot (async, before transact)
  let decryptedSnapshot: Uint8Array | null = null;
  let snapshotMeta: {
    snapshotId: string;
    parentSnapshotProof: string;
    parentSnapshotUpdateClocks: Record<string, number>;
    ciphertextHash: string;
  } | null = null;

  if (payload.snapshot) {
    const snap = payload.snapshot;
    throwIfDocumentProcessingCancelled(state);

    // Step 3a: signingPubKey membership confirmation
    const keyResult = await resolveSigningKey(snap.publicData.signingPubKey, state, {
      includeHistorical: true,
    });
    if (keyResult.status === "key_changed") {
      throw createVerificationFailedError(`TOFU key change: device ${keyResult.warning.deviceId}`);
    }
    if (
      keyResult.status === "not_found" &&
      state.rejectedSigningKeys.has(snap.publicData.signingPubKey)
    ) {
      throw createVerificationFailedError(
        `Snapshot: rejected signing key (cross-sign failed) ${snap.publicData.signingPubKey}`,
      );
    }
    if (keyResult.status === "not_found") {
      throw createVerificationFailedError(
        `Snapshot: unknown signing key ${snap.publicData.signingPubKey}`,
      );
    }
    // Signature verification is mandatory once the signing key is resolved.
    if (keyResult.status === "found") {
      const valid = await worker.verifyWsSignature({
        prefix: "refmd_snapshot",
        ciphertext: snap.ciphertext,
        nonce: snap.nonce,
        publicData: snap.publicData,
        signature: base64UrlDecode(snap.signature),
        signingPubKey: keyResult.key,
      });
      if (!valid) {
        throw createVerificationFailedError("Snapshot signature verification failed");
      }
    }

    // Step 3c: parentSnapshotProof verification via snapshotProofChain
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
        // Chain head's parentSnapshotProof should match this directly.
        const incomingCiphertextHash = base64UrlEncode(
          await worker.blake3Hash(base64UrlDecode(snap.ciphertext)),
        );
        await verifySnapshotProofChain(
          worker,
          payload.snapshotProofChain,
          snap.publicData.parentSnapshotProof,
          anchor.proofHash,
          snap.publicData.snapshotId,
          incomingCiphertextHash,
        );
      }
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
      parentSnapshotProof: snap.publicData.parentSnapshotProof,
      parentSnapshotUpdateClocks: snap.publicData.parentSnapshotUpdateClocks,
      ciphertextHash: base64UrlEncode(await worker.blake3Hash(base64UrlDecode(snap.ciphertext))),
    };
  }

  // Prepare state for update verification without committing to permanent state yet
  const prevActiveSnapshotId = state.activeSnapshotId;
  const prevKnownClocks = { ...state.knownClocks };
  const prevConfirmedClocks = { ...state.confirmedClocks };
  const prevSnapshotBaseClocks = { ...state.snapshotBaseClocks };

  if (snapshotMeta) {
    state.activeSnapshotId = snapshotMeta.snapshotId;
    state.snapshotBaseClocks = { ...snapshotMeta.parentSnapshotUpdateClocks };
    state.knownClocks = {};
    state.confirmedClocks = {};
    state._pendingOutOfOrderUpdates = [];
    clearOutOfOrderGapTimeout(state);
  }

  // Phase 2: Verify and decrypt all updates (async, before transact)
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
    state.snapshotBaseClocks = prevSnapshotBaseClocks;
    throw createRollbackAttackError("Version regression detected");
  }

  // Phase 3: Apply atomically inside transact (sync, no awaits)
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
  // Compute the proof hash for the active snapshot (not its parent's proof).
  if (snapshotMeta) {
    state.snapshotProofHash = await worker.computeSnapshotProof({
      ciphertextHash: snapshotMeta.ciphertextHash,
      parentProof: snapshotMeta.parentSnapshotProof,
      snapshotId: snapshotMeta.snapshotId,
    });
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

  state.initialized = true;
  queuePublicationAutoSync(documentId, state);
}

// ── Remote update ────────────────────────────────────────────

export async function handleRemoteUpdate(
  payload: UpdatePayload,
  state: DocumentState,
  documentId: string,
  localDeviceSigningPubKey?: string,
): Promise<void> {
  if (!state.initialized) {
    state._pendingRemoteEvents.push({ type: "update", payload });
    return;
  }

  // Reject updates from revoked devices on live path
  if (state.revokedSigningKeys.has(payload.publicData.signingPubKey)) {
    throw new Error(`Rejected live update from revoked device ${payload.publicData.signingPubKey}`);
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

  state._applyingRemote = true;
  try {
    Y.applyUpdate(state.yDoc, result.decrypted, "remote");
  } finally {
    state._applyingRemote = false;
  }

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

  // If this update is from our own device, advance localClock
  if (localDeviceSigningPubKey && payload.publicData.signingPubKey === localDeviceSigningPubKey) {
    if (payload.publicData.clock >= state.localClock) {
      state.localClock = payload.publicData.clock + 1;
    }
  }

  await drainOutOfOrderUpdates(state, documentId, localDeviceSigningPubKey);
}

function enqueueOutOfOrderUpdate(state: DocumentState, payload: UpdatePayload): void {
  const exists = state._pendingOutOfOrderUpdates.some(
    (queued) =>
      queued.publicData.refSnapshotId === payload.publicData.refSnapshotId &&
      queued.publicData.signingPubKey === payload.publicData.signingPubKey &&
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
        `Out-of-order update did not resolve: device=${first.publicData.signingPubKey} clock=${first.publicData.clock}`,
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
  localDeviceSigningPubKey?: string,
): Promise<void> {
  if (state._drainingOutOfOrderUpdates) return;
  state._drainingOutOfOrderUpdates = true;
  try {
    let progressed = true;
    while (progressed) {
      progressed = false;
      state._pendingOutOfOrderUpdates.sort(
        (a, b) =>
          a.publicData.signingPubKey.localeCompare(b.publicData.signingPubKey) ||
          a.publicData.clock - b.publicData.clock,
      );

      for (let index = 0; index < state._pendingOutOfOrderUpdates.length; index += 1) {
        const queued = state._pendingOutOfOrderUpdates[index]!;
        const lastClock = state.knownClocks[queued.publicData.signingPubKey];
        const expectedClock = lastClock === undefined ? 0 : lastClock + 1;
        if (
          queued.publicData.refSnapshotId === state.activeSnapshotId &&
          queued.publicData.clock === expectedClock
        ) {
          state._pendingOutOfOrderUpdates.splice(index, 1);
          await handleRemoteUpdate(queued, state, documentId, localDeviceSigningPubKey);
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

  if (state.revokedSigningKeys.has(payload.snapshot.publicData.signingPubKey)) {
    throw new Error(
      `Rejected live snapshot from revoked device ${payload.snapshot.publicData.signingPubKey}`,
    );
  }

  const worker = getDocumentCryptoWorker(state);
  const snap = payload.snapshot;
  if (snap.publicData.snapshotId === state.activeSnapshotId) {
    return;
  }

  // Resolve and verify signing key membership + TOFU
  const keyResult = await resolveSigningKey(snap.publicData.signingPubKey, state);
  if (keyResult.status === "key_changed") {
    throw createVerificationFailedError(`TOFU key change: device ${keyResult.warning.deviceId}`);
  }
  if (keyResult.status === "not_found") {
    throw createVerificationFailedError(
      `Remote snapshot: unknown signing key ${snap.publicData.signingPubKey}`,
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

  // Verify parentSnapshotProof matches the current active snapshot's proof hash.
  // state.snapshotProofHash IS the computed proof for the current active snapshot.
  // The new snapshot's parentSnapshotProof should match it directly.
  if (state.activeSnapshotId !== null && state.snapshotProofHash && state.snapshotCiphertextHash) {
    if (snap.publicData.parentSnapshotProof !== state.snapshotProofHash) {
      throw createVerificationFailedError(
        "Remote snapshot: parentSnapshotProof verification failed",
      );
    }
  }

  const valid = await worker.verifyWsSignature({
    prefix: "refmd_snapshot",
    ciphertext: snap.ciphertext,
    nonce: snap.nonce,
    publicData: snap.publicData,
    signature: base64UrlDecode(snap.signature),
    signingPubKey: keyResult.key,
  });
  if (!valid) {
    throw createVerificationFailedError("Remote snapshot signature verification failed");
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
  const remoteCiphertextHash = base64UrlEncode(
    await worker.blake3Hash(base64UrlDecode(snap.ciphertext)),
  );
  state.snapshotCiphertextHash = remoteCiphertextHash;
  state.snapshotProofHash = await worker.computeSnapshotProof({
    ciphertextHash: remoteCiphertextHash,
    parentProof: snap.publicData.parentSnapshotProof,
    snapshotId: snap.publicData.snapshotId,
  });

  const localDeviceSigningPublic =
    getLocalSigningPublicKeyBytes(state) ?? deviceState()?.deviceSigningPublic;
  state.snapshotBaseClocks = { ...snap.publicData.parentSnapshotUpdateClocks };
  state.knownClocks = {};
  state.confirmedClocks = {};
  state._pendingOutOfOrderUpdates = [];
  state.snapshotUpdatesCount = 0;
  state.localClock = getNextClockForDevice(
    state.knownClocks,
    getLocalSigningPubKeyB64(state) ??
      (localDeviceSigningPublic ? base64UrlEncode(localDeviceSigningPublic) : undefined),
  );

  // Build lastSavedState from server data only (not live Y.Doc which may have local edits)
  const serverDoc = new Y.Doc();
  Y.applyUpdateV2(serverDoc, decrypted, "remote");
  state.lastSavedState = Y.encodeStateAsUpdate(serverDoc);
  serverDoc.destroy();

  // Persist anti-rollback pin
  persistDocumentRollbackPin(documentId, state);
}
