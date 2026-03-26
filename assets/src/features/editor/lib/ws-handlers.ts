import * as Y from "yjs";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { resolveKekByVersion } from "@/shared/lib/crypto/kek-resolver";
import { encryptionApi } from "@/shared/api/encryption";
import { documentsApi } from "@/shared/api/documents";
import { deviceState } from "@/shared/lib/auth-state";
import { resolveSigningKey } from "./document-verification";
import type { DocumentState } from "./document-state-cache";

// ── Types for incoming payloads ──────────────────────────────

interface SnapshotPayload {
  ciphertext: string;
  nonce: string;
  signature: string;
  publicData: {
    docId: string;
    snapshotId: string;
    deviceId: string;
    signingPubKey: string;
    keyVersion: number;
    parentSnapshotId: string | null;
    parentSnapshotProof: string;
    parentSnapshotUpdateClocks: Record<string, number>;
  };
}

interface UpdatePayload {
  ciphertext: string;
  nonce: string;
  signature: string;
  version: number;
  publicData: {
    docId: string;
    deviceId: string;
    signingPubKey: string;
    keyVersion: number;
    refSnapshotId: string;
    clock: number;
    timestamp: number;
    updateHash: string;
  };
}

export interface DocumentPayload {
  snapshot: SnapshotPayload | null;
  updates: UpdatePayload[];
  snapshotProofChain: unknown[];
  latestVersion: number;
}

export interface UpdateSavedPayload {
  snapshotId: string;
  clock: number;
  version: number;
}

export interface UpdateSaveFailedPayload {
  snapshotId: string;
  clock: number;
  requiresNewSnapshot: boolean;
}

export interface SnapshotSavedPayload {
  snapshotId: string;
}

export interface SnapshotSaveFailedPayload {
  snapshot: SnapshotPayload | null;
  updates: UpdatePayload[];
  snapshotProofChain: unknown[];
}

interface SnapshotProofChainEntry {
  snapshotId: string;
  ciphertextHash: string;
  parentSnapshotProof: string;
}

// ── Initial document load ────────────────────────────────────
// Pattern: decrypt all async FIRST, then apply atomically in transact

export async function handleDocumentMessage(
  payload: DocumentPayload,
  state: DocumentState,
  documentId: string,
): Promise<void> {
  const worker = getCryptoWorker();

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

    // Step 3a: signingPubKey membership confirmation
    const keyResult = await resolveSigningKey(snap.publicData.signingPubKey, state);
    if (keyResult.status === "key_changed") {
      throw new Error(`TOFU key change: device ${keyResult.warning.deviceId}`);
    }
    if (
      keyResult.status === "not_found" &&
      state.rejectedSigningKeys.has(snap.publicData.signingPubKey)
    ) {
      throw new Error(
        `Snapshot: rejected signing key (cross-sign failed) ${snap.publicData.signingPubKey}`,
      );
    }
    // Signature verification (skip if signer is unknown former member)
    if (keyResult.status === "found") {
      const valid = await worker.verifyWsSignature({
        prefix: "refmd_snapshot",
        ciphertext: snap.ciphertext,
        nonce: snap.nonce,
        publicData: snap.publicData as unknown as Record<string, unknown>,
        signature: base64UrlDecode(snap.signature),
        signingPubKey: keyResult.key,
      });
      if (!valid) {
        throw new Error("Snapshot signature verification failed");
      }
    }

    // Step 3c: parentSnapshotProof verification via snapshotProofChain
    if (state.activeSnapshotId) {
      const snapshotChanged = snap.publicData.snapshotId !== state.activeSnapshotId;

      if (snapshotChanged && payload.snapshotProofChain.length === 0) {
        // Fail-closed: pin exists, snapshot changed, but no proof chain
        throw new Error("Snapshot changed but no proof chain provided (rollback attack)");
      }

      if (snapshotChanged && payload.snapshotProofChain.length > 0) {
        const pinnedProof = await worker.computeSnapshotProof({
          ciphertextHash: state.snapshotCiphertextHash,
          parentProof: state.snapshotProofHash,
          snapshotId: state.activeSnapshotId,
        });
        const incomingCiphertextHash = base64UrlEncode(
          await worker.blake3Hash(base64UrlDecode(snap.ciphertext)),
        );
        await verifySnapshotProofChain(
          worker,
          payload.snapshotProofChain as SnapshotProofChainEntry[],
          snap.publicData.parentSnapshotProof,
          pinnedProof,
          snap.publicData.snapshotId,
          incomingCiphertextHash,
        );
      }
    }

    // Step 3d: AEAD decryption
    await ensureDekCached(documentId, state.workspaceId, snap.publicData.keyVersion);
    decryptedSnapshot = await worker.decryptSnapshot({
      ciphertext: base64UrlDecode(snap.ciphertext),
      nonce: base64UrlDecode(snap.nonce),
      documentId,
      keyVersion: snap.publicData.keyVersion,
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

  if (snapshotMeta) {
    state.activeSnapshotId = snapshotMeta.snapshotId;
    state.knownClocks = {};
    state.confirmedClocks = {};
  }

  // Phase 2: Verify and decrypt all updates (async, before transact)
  let decryptedUpdates: DecryptedUpdate[];
  try {
    decryptedUpdates = await verifyAndDecryptUpdates(payload.updates, state, documentId, true);
  } catch (err) {
    // Rollback temporary state on verification failure
    state.activeSnapshotId = prevActiveSnapshotId;
    state.knownClocks = prevKnownClocks;
    state.confirmedClocks = prevConfirmedClocks;
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
    throw new Error("Version regression detected");
  }

  // Phase 3: Apply atomically inside transact (sync, no awaits)
  state.yDoc.transact(() => {
    if (decryptedSnapshot) {
      Y.applyUpdateV2(state.yDoc, decryptedSnapshot, "remote");
    }
    for (const { decrypted } of decryptedUpdates) {
      Y.applyUpdate(state.yDoc, decrypted, "remote");
    }
  }, "remote");

  // Commit snapshot metadata after successful verification + application
  if (snapshotMeta) {
    state.snapshotProofHash = snapshotMeta.parentSnapshotProof;
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

  state.initialized = true;
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
  const result = await verifyAndDecryptSingleUpdate(payload, state, documentId);
  if (!result) return; // stale/duplicate

  // Apply to live Y.Doc
  Y.applyUpdate(state.yDoc, result.decrypted, "remote");

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

  // If this update is from our own device, advance localClock
  if (localDeviceSigningPubKey && payload.publicData.signingPubKey === localDeviceSigningPubKey) {
    if (payload.publicData.clock >= state.localClock) {
      state.localClock = payload.publicData.clock + 1;
    }
  }
}

// ── Remote snapshot ──────────────────────────────────────────

export async function handleRemoteSnapshot(
  payload: { snapshotId: string; snapshot: SnapshotPayload },
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

  const worker = getCryptoWorker();
  const snap = payload.snapshot;

  // Resolve and verify signing key membership + TOFU
  const keyResult = await resolveSigningKey(snap.publicData.signingPubKey, state);
  if (keyResult.status === "key_changed") {
    throw new Error(`TOFU key change: device ${keyResult.warning.deviceId}`);
  }
  if (keyResult.status === "not_found") {
    throw new Error(`Remote snapshot: unknown signing key ${snap.publicData.signingPubKey}`);
  }

  // Verify parentSnapshotId matches current active snapshot
  if (
    state.activeSnapshotId !== null &&
    snap.publicData.parentSnapshotId !== state.activeSnapshotId
  ) {
    throw new Error(
      `Remote snapshot: parentSnapshotId mismatch (expected=${state.activeSnapshotId}, got=${snap.publicData.parentSnapshotId})`,
    );
  }

  // Verify parentSnapshotProof via BLAKE3 re-computation
  if (state.activeSnapshotId !== null) {
    const expectedProof = await worker.computeSnapshotProof({
      ciphertextHash: state.snapshotCiphertextHash,
      parentProof: state.snapshotProofHash,
      snapshotId: state.activeSnapshotId,
    });
    if (snap.publicData.parentSnapshotProof !== expectedProof) {
      throw new Error("Remote snapshot: parentSnapshotProof verification failed");
    }
  }

  const valid = await worker.verifyWsSignature({
    prefix: "refmd_snapshot",
    ciphertext: snap.ciphertext,
    nonce: snap.nonce,
    publicData: snap.publicData as unknown as Record<string, unknown>,
    signature: base64UrlDecode(snap.signature),
    signingPubKey: keyResult.key,
  });
  if (!valid) {
    throw new Error("Remote snapshot signature verification failed");
  }

  await ensureDekCached(documentId, state.workspaceId, snap.publicData.keyVersion);
  const decrypted = await worker.decryptSnapshot({
    ciphertext: base64UrlDecode(snap.ciphertext),
    nonce: base64UrlDecode(snap.nonce),
    documentId,
    keyVersion: snap.publicData.keyVersion,
  });

  Y.applyUpdateV2(state.yDoc, decrypted, "remote");

  // Advance local keyVersion if remote uses a newer DEK
  if (snap.publicData.keyVersion > state.keyVersion) {
    state.keyVersion = snap.publicData.keyVersion;
    checkRotationSnapshot(documentId, state);
  }

  state.activeSnapshotId = snap.publicData.snapshotId;
  state.snapshotProofHash = snap.publicData.parentSnapshotProof;
  state.snapshotCiphertextHash = base64UrlEncode(
    await worker.blake3Hash(base64UrlDecode(snap.ciphertext)),
  );

  // New snapshot: clocks are snapshot-scoped, start empty
  state.knownClocks = {};
  state.confirmedClocks = {};
  state.snapshotUpdatesCount = 0;
  // No post-snapshot updates in this message, so localClock starts at 0
  state.localClock = 0;

  // Build lastSavedState from server data only (not live Y.Doc which may have local edits)
  const serverDoc = new Y.Doc();
  Y.applyUpdateV2(serverDoc, decrypted, "remote");
  state.lastSavedState = Y.encodeStateAsUpdate(serverDoc);
  serverDoc.destroy();
}

// ── Confirmations ────────────────────────────────────────────

export function handleUpdateSaved(payload: UpdateSavedPayload, state: DocumentState): void {
  const deviceKey = deviceState()?.deviceSigningPublic;
  if (deviceKey) {
    const key = base64UrlEncode(deviceKey);
    state.knownClocks[key] = payload.clock;
    state.confirmedClocks[key] = payload.clock;
  }

  // Advance lastSavedState with confirmed update bytes
  if (state.pendingUpdateBytes && state.lastSavedState) {
    const serverDoc = new Y.Doc();
    Y.applyUpdate(serverDoc, state.lastSavedState, "remote");
    Y.applyUpdate(serverDoc, state.pendingUpdateBytes, "remote");
    state.lastSavedState = Y.encodeStateAsUpdate(serverDoc);
    serverDoc.destroy();
  }
  state.pendingUpdateBytes = null;
  state.pendingUpdateEnvelope = null;
  state.sending = false;

  if (payload.version > state.latestVersion) {
    state.latestVersion = payload.version;
  }
  state.snapshotUpdatesCount++;
  if (state.autoSync) state.autoSync.flush();
}

export function handleUpdateSaveFailed(
  payload: UpdateSaveFailedPayload,
  state: DocumentState,
): void {
  // Restore clock: if remote same-device update advanced it beyond our send, keep that.
  // Otherwise revert to pre-send value so retry uses the correct clock.
  const sentClock = state.preSendLocalClock;
  if (state.localClock === sentClock + 1) {
    state.localClock = sentClock;
  }
  state.pendingUpdateBytes = null;
  state.pendingUpdateEnvelope = null;
  state.sending = false;

  if (payload.requiresNewSnapshot) {
    state.error = "snapshot_mismatch";
    return;
  }

  if (state.autoSync) state.autoSync.notifyLocalEdit();
}

export function handleSnapshotSaved(payload: SnapshotSavedPayload, state: DocumentState): void {
  if (!state.pendingSnapshot) return;

  state.activeSnapshotId = payload.snapshotId;
  state.snapshotProofHash = state.pendingSnapshot.parentSnapshotProof;
  state.snapshotCiphertextHash = state.pendingSnapshot.ciphertextHash;
  // Build lastSavedState from snapshot content only (V2 -> V1 conversion)
  const serverDoc = new Y.Doc();
  Y.applyUpdateV2(serverDoc, state.pendingSnapshot.snapshotYjsState, "remote");
  state.lastSavedState = Y.encodeStateAsUpdate(serverDoc);
  serverDoc.destroy();
  state.snapshotUpdatesCount = 0;

  state.pendingSnapshot = null;
  state.pendingSnapshotEnvelope = null;
  state.sending = false;
  // Advance keyVersion on rotation snapshot confirmation (cutover point)
  if (state.pendingRotationKeyVersion !== null) {
    state.keyVersion = state.pendingRotationKeyVersion;
    state.pendingRotationKeyVersion = null;
  }
  state.pendingRotationSnapshot = false;
  state.knownClocks = {};
  state.confirmedClocks = {};
  state.localClock = 0;

  if (state.autoSync) state.autoSync.notifyLocalEdit();
}

export async function handleSnapshotSaveFailed(
  payload: SnapshotSaveFailedPayload,
  state: DocumentState,
  documentId: string,
): Promise<void> {
  state.pendingSnapshot = null;
  state.pendingSnapshotEnvelope = null;
  state.sending = false;

  if (payload.snapshot || payload.updates.length > 0) {
    // Derive best latestVersion from recovery updates (server doesn't send top-level latestVersion)
    let recoveryVersion = state.latestVersion;
    for (const u of payload.updates) {
      if (u.version > recoveryVersion) recoveryVersion = u.version;
    }
    try {
      await handleDocumentMessage(
        {
          snapshot: payload.snapshot,
          updates: payload.updates,
          snapshotProofChain: payload.snapshotProofChain,
          latestVersion: recoveryVersion,
        },
        state,
        documentId,
      );
      // Recovery succeeded: force snapshot creation on next auto-sync cycle
      state.snapshotUpdatesCount = Infinity;
      if (state.autoSync) state.autoSync.notifyLocalEdit();
    } catch (err) {
      console.error("[ws] snapshot recovery failed (non-fatal):", err);
      // Reset counter to suppress further snapshot attempts until next threshold
      state.snapshotUpdatesCount = 0;
    }
  } else {
    // No recovery data: force snapshot creation on next auto-sync cycle
    state.snapshotUpdatesCount = Infinity;
    if (state.autoSync) state.autoSync.notifyLocalEdit();
  }
}

// ── Internal helpers ─────────────────────────────────────────

interface DecryptedUpdate {
  decrypted: Uint8Array;
  deviceKey: string;
  clock: number;
}

// Verify signatures and decrypt all updates. Returns decrypted bytes for reuse.
async function verifyAndDecryptUpdates(
  updates: UpdatePayload[],
  state: DocumentState,
  documentId: string,
  allowUnknownSigner = false,
): Promise<DecryptedUpdate[]> {
  const results: DecryptedUpdate[] = [];

  for (const update of updates) {
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

// Verify signature, check clock contiguity, decrypt. Returns null if stale/duplicate.
async function verifyAndDecryptSingleUpdate(
  update: UpdatePayload,
  state: DocumentState,
  documentId: string,
  allowUnknownSigner = false,
): Promise<DecryptedUpdate | null> {
  const worker = getCryptoWorker();

  // signingPubKey membership confirmation + TOFU
  const keyResult = await resolveSigningKey(update.publicData.signingPubKey, state);
  if (keyResult.status === "key_changed") {
    throw new Error(`TOFU key change: device ${keyResult.warning.deviceId}`);
  }
  if (keyResult.status === "not_found") {
    if (state.rejectedSigningKeys.has(update.publicData.signingPubKey)) {
      throw new Error(
        `Update: rejected signing key (cross-sign failed) ${update.publicData.signingPubKey}`,
      );
    }
    if (!allowUnknownSigner) {
      throw new Error(`Update: unknown signing key ${update.publicData.signingPubKey}`);
    }
  }

  // Ed25519 signature verification (skip if signer is unknown former member)
  if (keyResult.status === "found") {
    const valid = await worker.verifyWsSignature({
      prefix: "refmd_update",
      ciphertext: update.ciphertext,
      nonce: update.nonce,
      publicData: update.publicData as unknown as Record<string, unknown>,
      signature: base64UrlDecode(update.signature),
      signingPubKey: keyResult.key,
    });
    if (!valid) {
      throw new Error("Update signature verification failed");
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
    throw new Error("Update hash verification failed");
  }

  // Step 2d/4b: refSnapshotId check
  if (
    state.activeSnapshotId !== null &&
    update.publicData.refSnapshotId !== state.activeSnapshotId
  ) {
    throw new Error(
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
      throw new Error(
        `Clock gap for device ${deviceKey}: expected=${lastClock + 1}, got=${update.publicData.clock}`,
      );
    }
  } else {
    // First update from this device in current snapshot scope must start at 0
    if (update.publicData.clock !== 0) {
      throw new Error(
        `First clock for device ${deviceKey} must be 0, got=${update.publicData.clock}`,
      );
    }
  }

  // Step 4d: AEAD decryption (before clock commit — failed decrypt must not poison clocks)
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

// ── Snapshot proof chain verification ────────────────────────
// 1. Chain head's parentSnapshotProof matches pinned proof hash
// 2. Each element: proof = BLAKE3(JCS({ciphertext_hash, parent_proof, snapshot_id}))
// 3. Computed proof matches next element's parentSnapshotProof

async function verifySnapshotProofChain(
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
    throw new Error("Snapshot proof chain: head does not match pinned proof hash");
  }

  // Verify chain terminates at the expected snapshot
  const tailEntry = chain[chain.length - 1]!;
  if (tailEntry.snapshotId !== expectedTailSnapshotId) {
    throw new Error(
      `Snapshot proof chain: tail snapshotId ${tailEntry.snapshotId} does not match expected ${expectedTailSnapshotId}`,
    );
  }

  // Verify tail ciphertext hash matches the actual received snapshot
  if (tailEntry.ciphertextHash !== expectedTailCiphertextHash) {
    throw new Error("Snapshot proof chain: tail ciphertextHash does not match received snapshot");
  }

  // Verify tail parentSnapshotProof matches the received snapshot's parentSnapshotProof
  if (tailEntry.parentSnapshotProof !== snapshotParentProof) {
    throw new Error(
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
        throw new Error(`Snapshot proof chain: link ${i} proof mismatch`);
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

  await resolveKekByVersion(workspaceId, key.kek_version);
  await worker.unwrapDek({
    encryptedDek: base64UrlDecode(key.encrypted_dek),
    nonce: base64UrlDecode(key.nonce),
    documentId,
    workspaceId,
    keyVersion: key.key_version,
    isActive: key.is_active,
    kekVersion: key.kek_version,
  });
}

/**
 * Check if post-rotation snapshot is needed after remote keyVersion advancement.
 * Fires async and sets pendingRotationSnapshot to trigger snapshot on next auto-sync cycle.
 */
function checkRotationSnapshot(documentId: string, state: DocumentState): void {
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
