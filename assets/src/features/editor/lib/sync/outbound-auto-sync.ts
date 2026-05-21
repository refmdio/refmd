import * as Y from "yjs";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { deviceState } from "@/entities/session";
import { clientError } from "@/shared/lib/logger";
import { getChannelState, pushUpdate, pushSnapshot } from "@/shared/lib/ws/phoenix-channel";
import type { AutoSyncHandle, DocumentState } from "../../model/document-state/types";
import {
  offlineMode,
  offlineReason,
  onOfflineModeChange,
} from "@/shared/lib/offline/offline-state";
import { getAuthTransportBackoffMs } from "@/shared/lib/ws/transport-coordinator";
import { cachePendingChanges } from "@/shared/lib/offline/cache/manager/write";
import { getLocalSigningKeyId } from "./share-identity";
import { ensureSharedDekCached, getDocumentDekCacheKey } from "./share-access";
import { getDocumentCryptoWorker } from "./crypto-worker";
import { canBufferDisconnectedChanges } from "./readiness";
import { hasUnsavedCanonicalText, refreshSavedBaselineToCurrent } from "./outbound-canonical";
import { armSaveAckWatchdog, clearSaveAckWatchdog } from "./outbound-save-watchdog";
import { createSyncGapError } from "./inbound-verify-decrypt";
import {
  buildDocumentOperationAdmission,
  hashSnapshotOperation,
  keyDirectoryAdvanceSymbol,
  prepareDocumentOperationAdmissionAuthority,
} from "./outbound-admission";

const THROTTLE_MS = 25;
const BLOCKED_RETRY_MS = 1_000;
const SNAPSHOT_UPDATE_THRESHOLD = 100;
const SNAPSHOT_RETRY_DELAY_MS = 5_000;

interface AutoSyncOptions {
  onSaveAckTimeout?: (kind: "update" | "snapshot") => void;
}

export function startAutoSync(
  documentId: string,
  state: DocumentState,
  options: AutoSyncOptions = {},
): AutoSyncHandle {
  const sharedText = state.yDoc.getText("content");
  let dirty = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let disposed = false;

  function scheduleSend(): void {
    if (timer || disposed) return;
    timer = setTimeout(async () => {
      timer = null;
      if (disposed) return;
      if (dirty) {
        // Offline mode: skip server sends, flush pending changes to IndexedDB
        if (offlineMode()) {
          const reason = offlineReason();
          if (reason === "auth_backoff") {
            scheduleBlockedRetry();
            return;
          }
          if (
            (reason === "ws_disconnect" || reason === "server_unreachable") &&
            !canBufferDisconnectedChanges(state)
          ) {
            scheduleBlockedRetry();
            return;
          }
          if (state.initialized && state.keyVersion > 0) {
            dirty = false;
            cachePendingChanges(documentId, state).catch(() => {});
          }
          return;
        }
        if (state.error || state.readOnly) {
          return;
        }
        if (
          !state.initialized ||
          !state.channel ||
          getChannelState(state.channel) !== "joined" ||
          state.sending ||
          state._reconnecting
        ) {
          scheduleBlockedRetry();
          return;
        }
        dirty = false;
        await sendPendingChanges(documentId, state, options).catch((err) => {
          dirty = true;
          scheduleBlockedRetry();
          clientError("auto_sync_send_failed", { documentId, error: err });
        });
      }
    }, THROTTLE_MS);
  }

  function scheduleBlockedRetry(): void {
    if (timer || disposed) return;
    const delay = Math.max(BLOCKED_RETRY_MS, getAuthTransportBackoffMs());
    timer = setTimeout(() => {
      timer = null;
      if (!disposed && dirty) {
        scheduleSend();
      }
    }, delay);
  }

  const observer = () => {
    if (state._applyingRemote) return;
    dirty = true;
    scheduleSend();
  };
  sharedText.observe(observer);

  if (hasUnsavedCanonicalText(state)) {
    dirty = true;
    scheduleSend();
  }

  // If DEK rotation was completed during init, trigger immediate snapshot
  if (state.pendingRotationSnapshot) {
    dirty = true;
    scheduleSend();
  }

  // When transitioning from offline to online, re-trigger send.
  // Only send if channel is still joined (short outage within heartbeat).
  // If the channel disconnected, triggerReconnect handles the delta rejoin flow.
  const cleanupOfflineWatch = onOfflineModeChange((isOffline) => {
    if (!isOffline && state.initialized && state.channel) {
      const chanState = getChannelState(state.channel);
      if (chanState === "joined") {
        dirty = true;
        scheduleSend();
      }
    }
  });

  return {
    dispose() {
      disposed = true;
      clearSaveAckWatchdog(state);
      cleanupOfflineWatch();
      sharedText.unobserve(observer);
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
    },
    notifyLocalEdit() {
      dirty = true;
      scheduleSend();
    },
    flush() {
      dirty = true;
      scheduleSend();
    },
    async flushNow() {
      if (disposed) return;
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      dirty = true;
      if (
        offlineMode() ||
        state.error ||
        state.readOnly ||
        !state.initialized ||
        !state.channel ||
        getChannelState(state.channel) !== "joined" ||
        state.sending ||
        state._reconnecting
      ) {
        scheduleSend();
        return;
      }
      dirty = false;
      await sendPendingChanges(documentId, state, options).catch((err) => {
        dirty = true;
        scheduleBlockedRetry();
        clientError("auto_sync_flush_failed", { documentId, error: err });
      });
    },
  };
}

// ── Send pending changes ─────────────────────────────────────

function isChannelJoined(state: DocumentState): boolean {
  return !!state.channel && getChannelState(state.channel) === "joined";
}

function retryAfterDisconnectedSend(documentId: string, state: DocumentState): void {
  state.sending = false;
  if (canBufferDisconnectedChanges(state)) {
    cachePendingChanges(documentId, state).catch(() => {});
    return;
  }
  state.autoSync?.notifyLocalEdit();
}

async function sendPendingChanges(
  documentId: string,
  state: DocumentState,
  options: AutoSyncOptions,
): Promise<void> {
  if (!state.initialized || !isChannelJoined(state) || state.sending || state.error) {
    return;
  }

  const device = deviceState();
  const deviceSigningKeyId = getLocalSigningKeyId(state) ?? device?.deviceSigningKeyId ?? undefined;
  if (!deviceSigningKeyId) return;

  state.sending = true;
  try {
    // Genesis snapshot (first snapshot for new document)
    if (state.activeSnapshotId === null) {
      if (state.pendingSnapshot) {
        state.sending = false;
        return;
      }
      await createAndSendGenesisSnapshot(documentId, state, options);
      return;
    }

    // Block update sends while snapshot is in flight
    if (state.pendingSnapshot) {
      state.sending = false;
      return;
    }

    const hasCanonicalChanges = hasUnsavedCanonicalText(state);

    // Check if we should create a snapshot first
    // Triggers: update count threshold OR pending DEK rotation
    if (state.snapshotUpdatesCount >= SNAPSHOT_UPDATE_THRESHOLD || state.pendingRotationSnapshot) {
      await createAndSendSnapshot(documentId, state, options);
      return;
    }

    if (!hasCanonicalChanges) {
      refreshSavedBaselineToCurrent(state);
      state.sending = false;
      return;
    }

    // Compute diff from last saved state
    let updateBytes: Uint8Array;
    if (state.lastSavedState) {
      const tempDoc = new Y.Doc();
      Y.applyUpdate(tempDoc, state.lastSavedState);
      const savedVector = Y.encodeStateVector(tempDoc);
      updateBytes = Y.encodeStateAsUpdate(state.yDoc, savedVector);
      tempDoc.destroy();

      if (updateBytes.length <= 2) {
        state.sending = false;
        return;
      }
    } else {
      updateBytes = Y.encodeStateAsUpdate(state.yDoc);
      if (updateBytes.length <= 2) {
        state.sending = false;
        return;
      }
    }

    const worker = getDocumentCryptoWorker(state);
    if (state.access.kind === "share") {
      await ensureSharedDekCached(state, documentId, state.keyVersion);
    }

    // 1. Encrypt
    const { ciphertext, nonce } = await worker.encryptContent({
      plaintext: updateBytes,
      documentId,
      keyVersion: state.keyVersion,
      cacheKey: getDocumentDekCacheKey(state, documentId),
    });
    const ciphertextB64 = base64UrlEncode(ciphertext);
    const nonceB64 = base64UrlEncode(nonce);

    const clock = state.localClock;
    const timestamp = Date.now();

    // 2. Compute update hash (snake_case keys to match server-side JCS)
    const updateHash = await worker.computeUpdateHash({
      clock,
      signing_key_id: deviceSigningKeyId,
      document_id: documentId,
      encrypted_content: ciphertextB64,
      key_version: state.keyVersion,
      nonce: nonceB64,
      ref_snapshot_id: state.activeSnapshotId,
      timestamp,
    });

    const admissionAuthority = await prepareDocumentOperationAdmissionAuthority(
      state,
      documentId,
      deviceSigningKeyId,
      "document_update_accepted",
      state.keyVersion,
    );

    // 3. Build public data
    const publicData: Record<string, unknown> = {
      docId: documentId,
      signingKeyId: deviceSigningKeyId,
      keyVersion: state.keyVersion,
      refSnapshotId: state.activeSnapshotId,
      clock,
      timestamp,
      updateHash,
      ...admissionAuthority.publicDataFields,
    };

    // 4. Sign
    const { signature } = await worker.signDocumentUpdate({
      ciphertext: ciphertextB64,
      nonce: nonceB64,
      workspaceId: state.workspaceId,
      publicData,
      authorityBoundary: admissionAuthority.authorityBoundary,
    });
    const { admission, keyDirectoryAdvance } = await buildDocumentOperationAdmission({
      documentId,
      state,
      eventType: "document_update_accepted",
      operationHash: updateHash,
      signature,
      keyVersion: state.keyVersion,
      authority: admissionAuthority,
    });

    // 5. Send
    const envelope = {
      ciphertext: ciphertextB64,
      nonce: nonceB64,
      signature,
      admission,
      publicData,
    };
    Object.defineProperty(envelope, keyDirectoryAdvanceSymbol, {
      value: keyDirectoryAdvance,
      enumerable: false,
    });
    state.pendingUpdateBytes = updateBytes;
    state.pendingUpdateEnvelope = envelope;
    state.preSendLocalClock = state.localClock;
    state.localClock++;

    if (!isChannelJoined(state)) {
      state.pendingUpdateBytes = null;
      state.pendingUpdateEnvelope = null;
      state.localClock = state.preSendLocalClock;
      retryAfterDisconnectedSend(documentId, state);
      return;
    }

    const pushed = pushUpdate(
      documentId,
      envelope,
      (resp: unknown) => {
        // Only reset on actual server error (not timeout — timeout fires
        // even on success because server uses {:noreply} + separate event)
        if (resp !== "timeout" && state.pendingUpdateBytes) {
          state.sending = false;
          state.pendingUpdateBytes = null;
          state.pendingUpdateEnvelope = null;
          state.localClock = state.preSendLocalClock;
          if (state.autoSync) state.autoSync.notifyLocalEdit();
        }
      },
      state.stateKey,
    );
    if (!pushed) {
      state.pendingUpdateBytes = null;
      state.pendingUpdateEnvelope = null;
      state.localClock = state.preSendLocalClock;
      retryAfterDisconnectedSend(documentId, state);
      return;
    }
    armSaveAckWatchdog(state, options.onSaveAckTimeout ?? (() => {}), "update");
  } catch (err) {
    state.sending = false;
    throw err;
  }
}

// ── Genesis snapshot ─────────────────────────────────────────

async function createAndSendGenesisSnapshot(
  documentId: string,
  state: DocumentState,
  options: AutoSyncOptions,
): Promise<void> {
  const worker = getDocumentCryptoWorker(state);
  const device = deviceState();
  const deviceSigningKeyId = getLocalSigningKeyId(state) ?? device?.deviceSigningKeyId ?? undefined;
  if (!deviceSigningKeyId) return;
  if (state.access.kind === "share") {
    await ensureSharedDekCached(state, documentId, state.keyVersion);
  }

  // Encode full Y.Doc state (V2 format)
  const yjsState = Y.encodeStateAsUpdateV2(state.yDoc);
  if (yjsState.length <= 2) {
    state.sending = false;
    return;
  }

  // Encrypt
  const { ciphertext, nonce } = await worker.encryptSnapshot({
    plaintext: yjsState,
    documentId,
    keyVersion: state.keyVersion,
    cacheKey: getDocumentDekCacheKey(state, documentId),
  });
  const ciphertextB64 = base64UrlEncode(ciphertext);
  const nonceB64 = base64UrlEncode(nonce);

  // Compute ciphertext hash for proof chain
  const ciphertextHash = base64UrlEncode(await worker.blake3Hash(ciphertext));

  // Genesis snapshot: empty parent
  const snapshotId = crypto.randomUUID();
  const admissionAuthority = await prepareDocumentOperationAdmissionAuthority(
    state,
    documentId,
    deviceSigningKeyId,
    "document_snapshot_accepted",
    state.keyVersion,
  );
  const publicData: Record<string, unknown> = {
    docId: documentId,
    snapshotId,
    signingKeyId: deviceSigningKeyId,
    keyVersion: state.keyVersion,
    parentSnapshotId: "GENESIS",
    parentProofHash: "GENESIS",
    parentSnapshotUpdateClocks: {},
    ...admissionAuthority.publicDataFields,
  };

  // Sign
  const { signature } = await worker.signDocumentSnapshot({
    ciphertext: ciphertextB64,
    nonce: nonceB64,
    workspaceId: state.workspaceId,
    publicData,
    authorityBoundary: admissionAuthority.authorityBoundary,
  });
  const { admission, keyDirectoryAdvance } = await buildDocumentOperationAdmission({
    documentId,
    state,
    eventType: "document_snapshot_accepted",
    operationHash: hashSnapshotOperation(ciphertext),
    signature,
    keyVersion: state.keyVersion,
    authority: admissionAuthority,
  });

  // Track pending snapshot
  state.pendingSnapshot = {
    snapshotId,
    parentSnapshotId: "GENESIS",
    ciphertextHash,
    parentProofHash: "GENESIS",
    snapshotYjsState: yjsState,
    knownClocksAtSend: { ...state.knownClocks },
  };

  // Send (reject callback only fires on server error, not timeout;
  // timeout always fires with {:noreply} but snapshot-saved/snapshot-save-failed
  // events are the authoritative confirmation)
  const snapshotEnvelope = {
    ciphertext: ciphertextB64,
    nonce: nonceB64,
    signature,
    admission,
    publicData,
  };
  Object.defineProperty(snapshotEnvelope, keyDirectoryAdvanceSymbol, {
    value: keyDirectoryAdvance,
    enumerable: false,
  });
  state.pendingSnapshotEnvelope = snapshotEnvelope;
  if (!isChannelJoined(state)) {
    state.pendingSnapshot = null;
    state.pendingSnapshotEnvelope = null;
    retryAfterDisconnectedSend(documentId, state);
    return;
  }

  const pushed = pushSnapshot(
    documentId,
    snapshotEnvelope,
    (resp: unknown) => {
      if (resp === "timeout") return;
      state.pendingSnapshot = null;
      state.pendingSnapshotEnvelope = null;
      state.sending = false;
      if (isPermanentPushFailure(resp)) {
        state.pendingRotationSnapshot = false;
      } else {
        scheduleSnapshotRetryIfNeeded(state);
      }
    },
    state.stateKey,
  );
  if (!pushed) {
    state.pendingSnapshot = null;
    state.pendingSnapshotEnvelope = null;
    retryAfterDisconnectedSend(documentId, state);
    return;
  }
  armSaveAckWatchdog(state, options.onSaveAckTimeout ?? (() => {}), "snapshot");
}

// ── Threshold snapshot ───────────────────────────────────────

async function createAndSendSnapshot(
  documentId: string,
  state: DocumentState,
  options: AutoSyncOptions,
): Promise<void> {
  if (!state.activeSnapshotId) {
    state.sending = false;
    return;
  }
  if (!state.snapshotProofHash || !state.snapshotCiphertextHash) {
    state.sending = false;
    state._forceCompleteReconnect = true;
    state._onRecoverableSyncGap?.(createSyncGapError("snapshot_baseline_missing"));
    return;
  }

  const worker = getDocumentCryptoWorker(state);
  const device = deviceState();
  const deviceSigningKeyId = getLocalSigningKeyId(state) ?? device?.deviceSigningKeyId ?? undefined;
  if (!deviceSigningKeyId) return;
  // Encode full Y.Doc state (V2 format)
  const yjsState = Y.encodeStateAsUpdateV2(state.yDoc);

  // For rotation snapshots, use the pending new key version
  const snapshotKeyVersion = state.pendingRotationKeyVersion ?? state.keyVersion;
  if (state.access.kind === "share") {
    await ensureSharedDekCached(state, documentId, snapshotKeyVersion);
  }

  // Encrypt
  const { ciphertext, nonce } = await worker.encryptSnapshot({
    plaintext: yjsState,
    documentId,
    keyVersion: snapshotKeyVersion,
    cacheKey: getDocumentDekCacheKey(state, documentId),
  });
  const ciphertextB64 = base64UrlEncode(ciphertext);
  const nonceB64 = base64UrlEncode(nonce);

  // Compute ciphertext hash
  const ciphertextHash = base64UrlEncode(await worker.blake3Hash(ciphertext));

  // state.snapshotProofHash already is the computed proof for the active snapshot.
  // The next snapshot must reference that proof directly as its parent anchor.
  const parentProofHash = state.snapshotProofHash;

  const snapshotId = crypto.randomUUID();
  const admissionAuthority = await prepareDocumentOperationAdmissionAuthority(
    state,
    documentId,
    deviceSigningKeyId,
    "document_snapshot_accepted",
    snapshotKeyVersion,
  );
  const publicData: Record<string, unknown> = {
    docId: documentId,
    snapshotId,
    signingKeyId: deviceSigningKeyId,
    keyVersion: snapshotKeyVersion,
    parentSnapshotId: state.activeSnapshotId,
    parentProofHash,
    parentSnapshotUpdateClocks: { ...state.knownClocks },
    ...admissionAuthority.publicDataFields,
  };

  // Sign
  const { signature } = await worker.signDocumentSnapshot({
    ciphertext: ciphertextB64,
    nonce: nonceB64,
    workspaceId: state.workspaceId,
    publicData,
    authorityBoundary: admissionAuthority.authorityBoundary,
  });
  const { admission, keyDirectoryAdvance } = await buildDocumentOperationAdmission({
    documentId,
    state,
    eventType: "document_snapshot_accepted",
    operationHash: hashSnapshotOperation(ciphertext),
    signature,
    keyVersion: snapshotKeyVersion,
    authority: admissionAuthority,
  });

  // Track pending snapshot
  state.pendingSnapshot = {
    snapshotId,
    parentSnapshotId: state.activeSnapshotId,
    ciphertextHash,
    parentProofHash,
    snapshotYjsState: yjsState,
    knownClocksAtSend: { ...state.knownClocks },
  };

  // Send (same pattern: ignore timeout, only handle server error)
  const snapshotEnvelope = {
    ciphertext: ciphertextB64,
    nonce: nonceB64,
    signature,
    admission,
    publicData,
  };
  Object.defineProperty(snapshotEnvelope, keyDirectoryAdvanceSymbol, {
    value: keyDirectoryAdvance,
    enumerable: false,
  });
  state.pendingSnapshotEnvelope = snapshotEnvelope;
  if (!isChannelJoined(state)) {
    state.pendingSnapshot = null;
    state.pendingSnapshotEnvelope = null;
    retryAfterDisconnectedSend(documentId, state);
    return;
  }

  const pushed = pushSnapshot(
    documentId,
    snapshotEnvelope,
    (resp: unknown) => {
      if (resp === "timeout") return;
      state.pendingSnapshot = null;
      state.pendingSnapshotEnvelope = null;
      state.sending = false;
      if (isPermanentPushFailure(resp)) {
        state.pendingRotationSnapshot = false;
      } else {
        scheduleSnapshotRetryIfNeeded(state);
      }
    },
    state.stateKey,
  );
  if (!pushed) {
    state.pendingSnapshot = null;
    state.pendingSnapshotEnvelope = null;
    retryAfterDisconnectedSend(documentId, state);
    return;
  }
  armSaveAckWatchdog(state, options.onSaveAckTimeout ?? (() => {}), "snapshot");
}

// ── Snapshot push failure handling ───────────────────────────

const PERMANENT_PUSH_ERRORS = new Set(["permission_denied", "device_revoked", "document_archived"]);

function isPermanentPushFailure(resp: unknown): boolean {
  if (typeof resp === "object" && resp !== null && "reason" in resp) {
    return PERMANENT_PUSH_ERRORS.has((resp as { reason: string }).reason);
  }
  return false;
}

function scheduleSnapshotRetryIfNeeded(state: DocumentState): void {
  setTimeout(() => {
    if (state.autoSync && !state.sending) {
      state.autoSync.notifyLocalEdit();
    }
  }, SNAPSHOT_RETRY_DELAY_MS);
}
