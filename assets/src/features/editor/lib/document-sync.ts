import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { resolveActiveKek, resolveKekByVersion } from "@/shared/lib/crypto/kek-resolver";
import { encryptionApi } from "@/shared/api/encryption";
import { documentsApi } from "@/shared/api/documents";
import { workspacesApi } from "@/shared/api/workspaces";
import { getPopHeaders } from "@/shared/lib/pop";
import { buildDeviceKeyCaches } from "./document-verification";
import { getDocumentState, setDocumentError } from "./document-state-cache";
import {
  joinDocument,
  leaveDocument,
  type DocumentChannelCallbacks,
} from "@/shared/lib/ws/phoenix-channel";
import {
  handleDocumentMessage,
  handleRemoteUpdate,
  handleRemoteSnapshot,
  handleUpdateSaved,
  handleUpdateSaveFailed,
  handleSnapshotSaved,
  handleSnapshotSaveFailed,
  type DocumentPayload,
  type UpdateSavedPayload,
  type UpdateSaveFailedPayload,
  type SnapshotSavedPayload,
  type SnapshotSaveFailedPayload,
} from "./ws-handlers";
import { startAutoSync } from "./auto-sync";
import { deviceState } from "@/shared/lib/auth-state";
import type { DocumentState } from "./document-state-cache";

export async function initializeDocumentSync(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<void> {
  try {
    await doInitializeDocumentSync(documentId, workspaceId, state);
  } catch (err) {
    state.initPromise = null;
    throw err;
  }
}

async function doInitializeDocumentSync(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<void> {
  const worker = getCryptoWorker();
  const device = deviceState();
  if (!device) throw new Error("Device state not available");

  const localDeviceSigningPubKey = device.deviceSigningPublic
    ? base64UrlEncode(device.deviceSigningPublic)
    : undefined;

  // 1. KEK resolution
  const { kekVersion: activeKekVersion } = await resolveActiveKek(workspaceId);

  // 2. DEK resolution: unwrap all versions
  const keysResponse = await encryptionApi.getDocumentKeys(documentId);
  const keys = keysResponse.keys;
  const activeKey = keys.find((k) => k.is_active);

  if (!activeKey) {
    throw new Error("No active DEK found for document");
  }

  // Resolve KEK for active DEK if it was wrapped with a different KEK version
  if (activeKey.kek_version !== activeKekVersion) {
    await resolveKekByVersion(workspaceId, activeKey.kek_version);
  }

  // Unwrap active DEK first (required for document open)
  await worker.unwrapDek({
    encryptedDek: base64UrlDecode(activeKey.encrypted_dek),
    nonce: base64UrlDecode(activeKey.nonce),
    documentId,
    workspaceId,
    keyVersion: activeKey.key_version,
    isActive: true,
    kekVersion: activeKey.kek_version,
  });

  // Unwrap old DEK versions (best-effort; failure does not block document open)
  for (const key of keys) {
    if (key.key_version === activeKey.key_version) continue;
    try {
      if (key.kek_version !== activeKekVersion) {
        await resolveKekByVersion(workspaceId, key.kek_version);
      }
      await worker.unwrapDek({
        encryptedDek: base64UrlDecode(key.encrypted_dek),
        nonce: base64UrlDecode(key.nonce),
        documentId,
        workspaceId,
        keyVersion: key.key_version,
        kekVersion: key.kek_version,
      });
    } catch {
      // Old DEK resolution is best-effort; on-demand via ensureDekCached
    }
  }
  state.dekResolved = true;
  state.keyVersion = activeKey.key_version;

  // 2b. DEK rotation completion (non-blocking — must not delay document display)
  state._retryDekRotation = () => completeDekRotationIfNeeded(documentId, workspaceId, state);
  completeDekRotationIfNeeded(documentId, workspaceId, state).catch(() => {});

  // Schedule delayed DEK rotation retry (handles deferred rotation after KEK rotation completes)
  setTimeout(async () => {
    if (state.initialized && state._retryDekRotation) {
      try {
        await state._retryDekRotation();
      } catch {
        // Best-effort; will retry on next document open
      }
    }
  }, 30_000);

  // 3. Build device key cache (signing key membership + TOFU)
  const cacheResult = await buildDeviceKeyCaches(workspaceId);
  if (cacheResult.status === "key_changed") {
    throw new Error(`TOFU key change detected: device ${cacheResult.warning.deviceId}`);
  }
  state.signingKeys = cacheResult.signingKeys;
  state.signingKeyOwners = cacheResult.signingKeyOwners;
  state.revokedSigningKeys = cacheResult.revokedSigningKeys;
  state.rejectedSigningKeys = cacheResult.rejectedSigningKeys;

  // 4. PoP for Channel join
  const popHeaders = await getPopHeaders();
  const joinParams: Record<string, unknown> = {
    pop_challenge: popHeaders["X-PoP-Challenge"],
    pop_signature: popHeaders["X-PoP-Signature"],
    mode: "complete",
  };

  // Send knownSnapshotId from in-memory state (same-session only)
  if (state.activeSnapshotId) {
    joinParams.knownSnapshotId = state.activeSnapshotId;
  }

  // 4. Wait for initial document event
  let documentTimeout: ReturnType<typeof setTimeout> | null = null;
  let rejectDocumentPromise: ((err: Error) => void) | null = null;
  const documentPromise = new Promise<DocumentPayload>((resolve, reject) => {
    rejectDocumentPromise = reject;
    documentTimeout = setTimeout(() => {
      reject(new Error("Timeout waiting for document event"));
    }, 30_000);

    state._onDocumentMessage = (payload: unknown) => {
      clearTimeout(documentTimeout!);
      documentTimeout = null;
      rejectDocumentPromise = null;
      resolve(payload as DocumentPayload);
    };
  });

  // Fail-closed: stop sync + disconnect channel + reject pending init
  function failClosed(reason: string, err?: unknown): void {
    if (state.error) return;
    if (err) console.error(`[ws] ${reason}:`, err);
    state.error = reason;
    state.initialized = false;
    state.initPromise = null;
    state.channel = null;
    setDocumentError(documentId, reason);
    if (documentTimeout) clearTimeout(documentTimeout);
    if (rejectDocumentPromise) rejectDocumentPromise(new Error(reason));
    if (state.autoSync) {
      state.autoSync.dispose();
      state.autoSync = null;
    }
    state.sending = false;
    state.pendingSnapshot = null;
    state.pendingUpdateBytes = null;
    leaveDocument(documentId);
  }

  // 5. Channel join
  const callbacks: DocumentChannelCallbacks = {
    onDocument: (payload) => {
      if (state._onDocumentMessage) {
        state._onDocumentMessage(payload as unknown as DocumentPayload);
        state._onDocumentMessage = null;
      }
    },
    onUpdate: (payload) => {
      handleRemoteUpdate(payload as any, state, documentId, localDeviceSigningPubKey).catch(
        (err) => {
          failClosed("verification_failed", err);
        },
      );
    },
    onSnapshot: (payload) => {
      handleRemoteSnapshot(payload as any, state, documentId).catch((err) => {
        failClosed("verification_failed", err);
      });
    },
    onUpdateSaved: (payload) => {
      handleUpdateSaved(payload as unknown as UpdateSavedPayload, state);
    },
    onUpdateSaveFailed: (payload) => {
      handleUpdateSaveFailed(payload as unknown as UpdateSaveFailedPayload, state);
      const p = payload as unknown as UpdateSaveFailedPayload;
      if (p.requiresNewSnapshot) {
        failClosed("snapshot_mismatch");
      }
    },
    onSnapshotSaved: (payload) => {
      handleSnapshotSaved(payload as unknown as SnapshotSavedPayload, state);
    },
    onSnapshotSaveFailed: (payload) => {
      handleSnapshotSaveFailed(
        payload as unknown as SnapshotSaveFailedPayload,
        state,
        documentId,
      ).catch((err) => {
        failClosed("verification_failed", err);
      });
    },
    onEphemeralMessage: () => {
      // Ephemeral handling is Phase 4-23
    },
    onUnauthorized: () => {
      failClosed("unauthorized");
    },
    onError: (reason) => {
      if (reason === "document_not_found" || reason === "document_error") {
        failClosed(String(reason));
      } else {
        console.error("[ws] Channel error:", reason);
      }
    },
    onClose: () => {
      // Only fail-closed if state is still alive (not a normal teardown eviction)
      if (state.initialized && getDocumentState(documentId)) {
        failClosed("disconnected");
      }
    },
  };

  let channel;
  try {
    channel = await joinDocument(documentId, joinParams, callbacks);
  } catch (err) {
    if (documentTimeout) clearTimeout(documentTimeout);
    state._onDocumentMessage = null;
    throw err;
  }
  state.channel = channel;

  // Guard: if state was torn down during async init, leave immediately
  if (!getDocumentState(documentId)) {
    leaveDocument(documentId);
    return;
  }

  // 6. Wait for and process initial document data
  let documentPayload: DocumentPayload;
  try {
    documentPayload = await documentPromise;
  } catch (err) {
    failClosed("initial_load_failed", err);
    throw err;
  }
  try {
    await handleDocumentMessage(documentPayload, state, documentId);
  } catch (err) {
    failClosed("initial_load_failed", err);
    throw err;
  }

  // Guard: check again after async message processing
  if (!getDocumentState(documentId)) {
    leaveDocument(documentId);
    return;
  }

  // 7. Derive localClock: find max clock from updates[] for this device
  // (parentSnapshotUpdateClocks values are pre-snapshot; post-snapshot clocks start at 0)
  if (localDeviceSigningPubKey) {
    let maxClock = -1;
    for (const update of documentPayload.updates) {
      if (
        update.publicData.signingPubKey === localDeviceSigningPubKey &&
        update.publicData.clock > maxClock
      ) {
        maxClock = update.publicData.clock;
      }
    }
    state.localClock = maxClock + 1;
  }

  // 8. Detect pending rotation: server flag OR stale title (crash-resilient)
  if (!state.pendingRotationSnapshot) {
    try {
      const docMeta = await documentsApi.get(documentId);
      if (docMeta.needs_rotation_snapshot) {
        state.pendingRotationSnapshot = true;
      }
      // Immediate title re-encryption if stale (crash recovery)
      if (
        docMeta.encrypted_title_key_version &&
        docMeta.encrypted_title_key_version < state.keyVersion
      ) {
        await reEncryptTitleIfNeeded(documentId, workspaceId, state);
      }
    } catch {
      // Non-blocking
    }
  }

  // 9. Start auto-sync
  state.autoSync = startAutoSync(documentId, state);
}

export function teardownDocumentSync(documentId: string, state: DocumentState): void {
  if (state.autoSync) {
    state.autoSync.dispose();
    state.autoSync = null;
  }
  leaveDocument(documentId);
  state.channel = null;
}

/**
 * Detect needs_dek_rotation and complete rotation if needed.
 * device.md step 8: other workspace members (document:write + KEK)
 * detect the flag on document access and auto-complete the rotation.
 * Errors are caught silently — rotation failure must not block document viewing.
 */
async function completeDekRotationIfNeeded(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<void> {
  try {
    await doCompleteDekRotation(documentId, workspaceId, state);
  } catch (err) {
    console.error("[sync] DEK rotation completion failed (non-blocking):", err);
    // Another client may have completed the rotation. Refresh active DEK version.
    try {
      const w = getCryptoWorker();
      const refreshed = await encryptionApi.getDocumentKeys(documentId);
      const refreshedActive = refreshed.keys.find((k) => k.is_active);
      if (refreshedActive && refreshedActive.key_version !== state.keyVersion) {
        await resolveKekByVersion(workspaceId, refreshedActive.kek_version);
        await w.unwrapDek({
          encryptedDek: base64UrlDecode(refreshedActive.encrypted_dek),
          nonce: base64UrlDecode(refreshedActive.nonce),
          documentId,
          workspaceId,
          keyVersion: refreshedActive.key_version,
          isActive: true,
          kekVersion: refreshedActive.kek_version,
        });
        state.keyVersion = refreshedActive.key_version;
      }
    } catch {
      // Best-effort refresh
    }
  }
}

async function doCompleteDekRotation(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<void> {
  const doc = await documentsApi.get(documentId);
  if (!doc?.needs_dek_rotation) return;

  // Step 5 must complete before step 6 (device.md)
  const ws = await workspacesApi.get(workspaceId);
  if (ws.needs_kek_rotation) return;

  // Re-resolve active KEK (may have changed since init if KEK rotation just completed)
  await resolveActiveKek(workspaceId);

  const worker = getCryptoWorker();
  const nextKeyVersion = state.keyVersion + 1;

  // Generate new DEK without setting it as active (setActive: false).
  // Active version is only updated after successful server save.
  const {
    encryptedDek,
    nonce,
    keyVersion: kekVersion,
  } = await worker.generateDek(documentId, workspaceId, nextKeyVersion, false);

  // Save to server (also clears needs_dek_rotation flag and updates min_dek_version)
  try {
    await encryptionApi.createDocumentKey(documentId, {
      encrypted_dek: base64UrlEncode(encryptedDek),
      nonce: base64UrlEncode(nonce),
      key_version: nextKeyVersion,
      kek_version: kekVersion,
    });
  } catch (err) {
    // POST failed: evict the speculative DEK from cache
    await worker.evictDek(documentId, nextKeyVersion).catch(() => {});
    throw err;
  }

  // POST succeeded: now activate the new DEK
  await worker.unwrapDek({
    encryptedDek: base64UrlDecode(base64UrlEncode(encryptedDek)),
    nonce: base64UrlDecode(base64UrlEncode(nonce)),
    documentId,
    workspaceId,
    keyVersion: nextKeyVersion,
    isActive: true,
    kekVersion: kekVersion,
  });

  state.keyVersion = nextKeyVersion;

  // Immediate title re-encryption (independent of snapshot)
  try {
    await reEncryptTitleIfNeeded(documentId, workspaceId, state);
  } catch (err) {
    console.error("[sync] Title re-encryption failed (will retry on next open):", err);
  }

  // Set snapshot trigger (post-rotation snapshot requirement)
  state.pendingRotationSnapshot = true;
}

/**
 * Re-encrypt document title if its key version doesn't match the active DEK.
 * Executed immediately after DEK rotation (not deferred to Snapshot).
 * Also handles crash recovery: stale title detected on document open.
 */
async function reEncryptTitleIfNeeded(
  documentId: string,
  _workspaceId: string,
  state: DocumentState,
): Promise<void> {
  const worker = getCryptoWorker();

  let doc: Awaited<ReturnType<typeof documentsApi.get>>;
  try {
    doc = await documentsApi.get(documentId);
  } catch {
    return;
  }

  if (!doc.encrypted_title || !doc.encrypted_title_nonce || !doc.encrypted_title_key_version) {
    return;
  }

  // Only re-encrypt if title is on an older DEK version
  if (doc.encrypted_title_key_version >= state.keyVersion) return;

  const oldKeyVersion = doc.encrypted_title_key_version;
  const title = await worker.decryptTitle({
    encrypted: base64UrlDecode(doc.encrypted_title),
    nonce: base64UrlDecode(doc.encrypted_title_nonce),
    documentId,
    keyVersion: oldKeyVersion,
  });

  const newKeyVersion = state.keyVersion;
  const { encrypted, nonce } = await worker.encryptTitle({
    title,
    documentId,
    keyVersion: newKeyVersion,
  });

  await documentsApi.update(documentId, {
    encrypted_title: base64UrlEncode(encrypted),
    encrypted_title_nonce: base64UrlEncode(nonce),
    encrypted_title_key_version: newKeyVersion,
  });
}
