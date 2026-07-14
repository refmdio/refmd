import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { deviceState } from "@/entities/session";
import { clientError } from "@/shared/lib/logger";
import { getChannelState, pushUpdate, pushSnapshot } from "@/shared/lib/ws/phoenix-channel";
import { getDocumentVerificationCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import { encodeCanonicalStateAsUpdateV2 } from "@/shared/lib/yjs/canonical-document";
import type { AutoSyncHandle, DocumentState } from "../../model/document-state/types";
import type { WriteSessionState } from "../../model/document-state/types";
import {
  offlineMode,
  offlineReason,
  onOfflineModeChange,
} from "@/shared/lib/offline/offline-state";
import { getAuthTransportBackoffMs } from "@/shared/lib/ws/transport-coordinator";
import { cacheDocumentStateAndPendingChanges } from "@/shared/lib/offline/cache/manager/write";
import { getLocalSigningKeyId } from "./share-identity";
import { ensureSharedDekCached, getDocumentDekCacheKey } from "./share-access";
import { getDocumentCryptoWorker } from "./crypto-worker";
import { canBufferDisconnectedChanges } from "./readiness";
import {
  encodeExistingSnapshotCanonicalUpdate,
  hasUnsavedCanonicalText,
} from "./outbound-canonical";
import { armSaveAckWatchdog, clearSaveAckWatchdog } from "./outbound-save-watchdog";
import {
  createSyncGapError,
  ensureDekCached,
  refreshVerifiedWriteSessions,
} from "./inbound-verify-decrypt";
import {
  buildDocumentOperationAdmission,
  documentOperationAdmissionForTransport,
  ensureDocumentWriteSession,
  hashSnapshotOperation,
  keyDirectoryAdvanceSymbol,
  persistDocumentWriteSession,
  prepareDocumentOperationAdmissionAuthority,
} from "./outbound-admission";
import { recordSyncPerf } from "./perf";
import { computeDocumentUpdateHash } from "./update-hash";
import { nextLocalClockForDevice } from "./local-clock";

function getOfflineCacheOptions(state: DocumentState, documentId: string) {
  return state.access.kind === "share"
    ? {
        worker: getDocumentCryptoWorker(state),
        cacheKey: getDocumentDekCacheKey(state, documentId),
      }
    : undefined;
}

const THROTTLE_MS = 64;
const BLOCKED_RETRY_MS = 1_000;
const WRITE_SESSION_PREPARE_RETRY_MS = 1_000;
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
  let immediateSendGeneration = 0;
  let immediateSendQueued = false;
  let writeSessionRetryTimer: ReturnType<typeof setTimeout> | null = null;
  let writeSessionExpiryTimer: ReturnType<typeof setTimeout> | null = null;
  let disposed = false;
  const inFlightSends = new Set<Promise<void>>();

  function trackSend(send: Promise<void>): Promise<void> {
    inFlightSends.add(send);
    return send.finally(() => inFlightSends.delete(send));
  }
  let explicitLocalEditPending = false;

  void warmDocumentVerificationPath(documentId);

  function clearWriteSessionRetry(): void {
    if (writeSessionRetryTimer) {
      clearTimeout(writeSessionRetryTimer);
      writeSessionRetryTimer = null;
    }
  }

  function clearWriteSessionExpiry(): void {
    if (writeSessionExpiryTimer) {
      clearTimeout(writeSessionExpiryTimer);
      writeSessionExpiryTimer = null;
    }
  }

  function canPrepareWriteSession(): boolean {
    return (
      !disposed &&
      !offlineMode() &&
      !state.error &&
      !state.readOnly &&
      state.initialized &&
      state.activeSnapshotId !== null &&
      state.keyVersion > 0 &&
      !state.sending &&
      !state.pendingUpdateEnvelope &&
      !state.pendingSnapshotEnvelope &&
      !!state.channel &&
      getChannelState(state.channel) === "joined" &&
      !state._reconnecting
    );
  }

  function scheduleWriteSessionIdleExpiry(): void {
    clearWriteSessionExpiry();
    const session = state.writeSession;
    if (!session || disposed) return;
    const delay = Math.max(WRITE_SESSION_PREPARE_RETRY_MS, session.expiresAtMs - Date.now());
    writeSessionExpiryTimer = setTimeout(() => {
      writeSessionExpiryTimer = null;
      if (state.writeSession !== session) return;
      state.writeSession = null;
      state.writeSessionReadyAt = null;
    }, delay);
  }

  function scheduleWriteSessionRetry(): void {
    if (writeSessionRetryTimer || disposed) return;
    const delay = Math.max(WRITE_SESSION_PREPARE_RETRY_MS, getAuthTransportBackoffMs());
    writeSessionRetryTimer = setTimeout(() => {
      writeSessionRetryTimer = null;
      void prepareWriteSession("retry");
    }, delay);
  }

  function writeSessionErrorMessage(err: unknown): string {
    if (err instanceof Error) return err.message;
    if (typeof err === "string") return err;
    try {
      return JSON.stringify(err);
    } catch {
      return String(err);
    }
  }

  function isReadyWriteSession(session: WriteSessionState): boolean {
    return state.writeSession === session && state.writeSessionReadyAt !== null;
  }

  async function prepareWriteSession(
    reason: "initial" | "retry" | "snapshot" | "manual" = "manual",
    forceRefresh = false,
  ): Promise<boolean> {
    if (!canPrepareWriteSession()) return false;
    const device = deviceState();
    const deviceSigningKeyId =
      getLocalSigningKeyId(state) ?? device?.deviceSigningKeyId ?? undefined;
    if (!deviceSigningKeyId) return false;

    clearWriteSessionRetry();
    const startedAt = performance.now();
    try {
      const session = await ensureDocumentWriteSession({
        documentId,
        state,
        signingKeyId: deviceSigningKeyId,
        keyVersion: state.keyVersion,
        nextCiphertextBytes: 0,
        forceRefresh,
      });
      if (!forceRefresh && isReadyWriteSession(session)) {
        state.writeSessionError = null;
        scheduleWriteSessionIdleExpiry();
        recordSyncPerf("write_session_already_ready", {
          documentId,
          reason,
          elapsedMs: performance.now() - startedAt,
        });
        return true;
      }
      await persistDocumentWriteSession({ documentId, state, session, markReady: false });
      await warmDocumentWritePath(documentId, state, session);
      const refreshedWriteSessions = await refreshVerifiedWriteSessions(state, documentId);
      if (state.writeSession === session) {
        state.writeSessionReadyAt = Date.now();
        state.writeSessionError = null;
      }
      clearWriteSessionRetry();
      scheduleWriteSessionIdleExpiry();
      recordSyncPerf("write_session_ready", {
        documentId,
        reason,
        elapsedMs: performance.now() - startedAt,
      });
      if (refreshedWriteSessions > 0) {
        recordSyncPerf("write_session_cache_refreshed", {
          documentId,
          count: refreshedWriteSessions,
        });
      }
      return true;
    } catch (err) {
      clearWriteSessionExpiry();
      handleAdmissionPushFailure(err, state);
      state.writeSessionError = writeSessionErrorMessage(err);
      recordSyncPerf("write_session_prepare_failed", {
        documentId,
        reason,
        error: state.writeSessionError,
        elapsedMs: performance.now() - startedAt,
      });
      if (canPrepareWriteSession()) scheduleWriteSessionRetry();
      return false;
    }
  }

  async function runScheduledSend(): Promise<void> {
    if (disposed) return;
    if (!dirty) return;
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
        cacheDocumentStateAndPendingChanges(
          documentId,
          state.workspaceId,
          state,
          getOfflineCacheOptions(state, documentId),
        ).catch(() => {});
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
      state._reconnecting
    ) {
      scheduleBlockedRetry();
      return;
    }
    if (state.sending) return;
    dirty = false;
    explicitLocalEditPending = false;
    await trackSend(sendPendingChanges(documentId, state, options)).catch((err) => {
      dirty = true;
      scheduleBlockedRetry();
      clientError("auto_sync_send_failed", { documentId, error: err });
    });
  }

  function scheduleSend(options: { resetPending?: boolean; immediate?: boolean } = {}): void {
    if (disposed) return;
    if (timer) {
      if (!options.resetPending) return;
      clearTimeout(timer);
      timer = null;
    }
    if (immediateSendQueued) {
      if (!options.resetPending) return;
      immediateSendGeneration++;
      immediateSendQueued = false;
    }
    if (options.immediate) {
      const generation = ++immediateSendGeneration;
      immediateSendQueued = true;
      queueMicrotask(() => {
        if (generation !== immediateSendGeneration || disposed) return;
        immediateSendQueued = false;
        void runScheduledSend();
      });
      return;
    }
    timer = setTimeout(async () => {
      timer = null;
      await runScheduledSend();
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

  let observerCheckQueued = false;
  const isBridgeOrigin = (origin: unknown): origin is string =>
    typeof origin === "string" && origin.startsWith("bridge:");
  const observer = (
    _event: unknown,
    transaction?: {
      origin?: unknown;
    },
  ) => {
    if (state._applyingRemote) return;
    if (observerCheckQueued) return;
    const origin = transaction?.origin;
    observerCheckQueued = true;
    queueMicrotask(() => {
      observerCheckQueued = false;
      if (disposed || state._applyingRemote) return;
      const hasCanonicalChanges = hasUnsavedCanonicalText(state);
      if (isBridgeOrigin(origin) && !explicitLocalEditPending) {
        if (hasCanonicalChanges) {
          recordSyncPerf("bridge_edit_observed", {
            documentId,
            hadPendingLocalEdit: dirty,
            originString: origin,
          });
          dirty = true;
          scheduleSend({ resetPending: true });
          return;
        }
        recordSyncPerf("local_edit_ignored", {
          documentId,
          originString: origin,
        });
        return;
      }
      if (!hasCanonicalChanges) {
        return;
      }
      recordSyncPerf("local_edit_observed", {
        documentId,
        originType: typeof origin,
        originConstructor:
          origin && typeof origin === "object" ? (origin.constructor?.name ?? null) : null,
        originString: typeof origin === "string" ? origin : null,
      });
      explicitLocalEditPending = false;
      dirty = true;
      scheduleSend({ resetPending: true });
    });
  };
  sharedText.observe(observer);

  if (hasUnsavedCanonicalText(state)) {
    const hasPreAutoSyncUserEdit = state._preAutoSyncUserEdit;
    state._preAutoSyncUserEdit = false;
    if (
      state.activeSnapshotId !== null &&
      !state.loadedFromOfflineCache &&
      !state.pendingRotationSnapshot &&
      !hasPreAutoSyncUserEdit
    ) {
      recordSyncPerf("initial_unsaved_canonical_ignored", {
        documentId,
        accessKind: state.access.kind,
      });
      dirty = true;
      scheduleSend();
    } else {
      if (hasPreAutoSyncUserEdit) {
        recordSyncPerf("pre_auto_sync_user_edit_queued", {
          documentId,
          accessKind: state.access.kind,
        });
      }
      dirty = true;
      scheduleSend();
    }
  }

  // If DEK rotation was completed during init, trigger immediate snapshot
  if (state.pendingRotationSnapshot) {
    dirty = true;
    scheduleSend();
  }

  void prepareWriteSession("initial");

  // When transitioning from offline to online, re-trigger send.
  // Only send if channel is still joined (short outage within heartbeat).
  // If the channel disconnected, triggerReconnect handles the delta rejoin flow.
  const cleanupOfflineWatch = onOfflineModeChange((isOffline) => {
    if (!isOffline && state.initialized && state.channel) {
      const chanState = getChannelState(state.channel);
      if (chanState === "joined") {
        void prepareWriteSession("retry");
        dirty = true;
        scheduleSend();
      }
    }
  });

  return {
    dispose() {
      disposed = true;
      clearSaveAckWatchdog(state);
      clearWriteSessionRetry();
      clearWriteSessionExpiry();
      cleanupOfflineWatch();
      sharedText.unobserve(observer);
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
    },
    async drain() {
      while (inFlightSends.size > 0) {
        await Promise.allSettled(inFlightSends);
      }
    },
    notifyLocalEdit() {
      explicitLocalEditPending = true;
      dirty = true;
      scheduleSend({ resetPending: true });
    },
    prepareWriteSession,
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
        state._reconnecting
      ) {
        scheduleSend();
        return;
      }
      if (state.sending) return;
      dirty = false;
      explicitLocalEditPending = false;
      await trackSend(sendPendingChanges(documentId, state, options)).catch((err) => {
        dirty = true;
        scheduleBlockedRetry();
        clientError("auto_sync_flush_failed", { documentId, error: err });
      });
    },
  };
}

async function warmDocumentVerificationPath(documentId: string): Promise<void> {
  const startedAt = performance.now();
  try {
    await getDocumentVerificationCryptoWorker(documentId).isReady();
    recordSyncPerf("verification_path_warmed", {
      documentId,
      elapsedMs: performance.now() - startedAt,
    });
  } catch (err) {
    recordSyncPerf("verification_path_warm_failed", {
      documentId,
      elapsedMs: performance.now() - startedAt,
      error: err instanceof Error ? err.message : String(err),
    });
  }
}

async function warmDocumentWritePath(
  documentId: string,
  state: DocumentState,
  session: WriteSessionState,
): Promise<void> {
  const startedAt = performance.now();
  const worker = getDocumentCryptoWorker(state);
  await ensureDekCached(documentId, state.workspaceId, state.keyVersion, state);
  const { ciphertext, nonce } = await worker.encryptContent({
    plaintext: new Uint8Array(0),
    documentId,
    keyVersion: state.keyVersion,
    cacheKey: getDocumentDekCacheKey(state, documentId),
  });
  await worker.decryptContent({
    ciphertext,
    nonce,
    documentId,
    keyVersion: state.keyVersion,
    cacheKey: getDocumentDekCacheKey(state, documentId),
  });
  const ciphertextB64 = base64UrlEncode(ciphertext);
  const nonceB64 = base64UrlEncode(nonce);
  const clock = state.localClock;
  const timestamp = Date.now();
  const updateHash = computeDocumentUpdateHash({
    clock,
    signing_key_id: session.signingKeyId,
    document_id: documentId,
    encrypted_content: ciphertextB64,
    key_version: state.keyVersion,
    nonce: nonceB64,
    ref_snapshot_id: state.activeSnapshotId,
    timestamp,
  });
  const writeSessionCounter = 1;
  await worker.signDocumentUpdate({
    ciphertext: ciphertextB64,
    nonce: nonceB64,
    workspaceId: state.workspaceId,
    publicData: {
      docId: documentId,
      signingKeyId: session.signingKeyId,
      keyVersion: state.keyVersion,
      refSnapshotId: state.activeSnapshotId,
      clock,
      timestamp,
      updateHash,
      ...session.publicDataFields,
      writeSessionCounter,
    },
    authorityBoundary: {
      ...session.authorityBoundary,
      write_session_counter: writeSessionCounter,
    },
  });
  recordSyncPerf("write_path_warmed", {
    documentId,
    elapsedMs: performance.now() - startedAt,
  });
}

// ── Send pending changes ─────────────────────────────────────

function isChannelJoined(state: DocumentState): boolean {
  return !!state.channel && getChannelState(state.channel) === "joined";
}

function retryAfterDisconnectedSend(documentId: string, state: DocumentState): void {
  state.sending = false;
  if (canBufferDisconnectedChanges(state)) {
    cacheDocumentStateAndPendingChanges(
      documentId,
      state.workspaceId,
      state,
      getOfflineCacheOptions(state, documentId),
    ).catch(() => {});
    return;
  }
  state.autoSync?.notifyLocalEdit();
}

function pushFailureReason(resp: unknown): string | null {
  return typeof resp === "object" && resp !== null && "reason" in resp
    ? String((resp as { reason: unknown }).reason)
    : null;
}

function handleAdmissionPushFailure(resp: unknown, state: DocumentState): boolean {
  const reason = pushFailureReason(resp);
  if (
    reason === "admission_invalid" ||
    reason === "write_session_invalid" ||
    reason === "write_session_expired"
  ) {
    state._admissionDirectoryRefreshRequired = true;
    state.writeSession = null;
    state.writeSessionPromise = null;
    state.writeSessionReadyAt = null;
    return true;
  }
  return false;
}

function handleOversizedUpdatePushFailure(resp: unknown, state: DocumentState): boolean {
  if (pushFailureReason(resp) !== "document_update_payload_too_large") return false;
  state.snapshotUpdatesCount = Infinity;
  state._admissionDirectoryRefreshRequired = true;
  return true;
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
    const sendStartedAt = performance.now();
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
      state.sending = false;
      return;
    }

    // Compute a canonical Markdown diff. ProseMirror XML is a WYSIWYG-derived view state and
    // must not be persisted into document updates.
    const updateResult = encodeExistingSnapshotCanonicalUpdate(state);
    if (updateResult.kind === "missing_baseline") {
      state.sending = false;
      state._forceCompleteReconnect = true;
      state._onRecoverableSyncGap?.(createSyncGapError("canonical_baseline_missing"));
      return;
    }
    if (updateResult.kind === "structural_unavailable") {
      state.sending = false;
      state._forceCompleteReconnect = true;
      state._onRecoverableSyncGap?.(createSyncGapError("canonical_structural_diff_unavailable"));
      return;
    }
    if (updateResult.kind === "empty") {
      state.sending = false;
      return;
    }
    const updateBytes = updateResult.update;
    recordSyncPerf("update_encoded", {
      documentId,
      elapsedMs: performance.now() - sendStartedAt,
      bytes: updateBytes.length,
    });

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
    recordSyncPerf("update_encrypted", {
      documentId,
      elapsedMs: performance.now() - sendStartedAt,
    });
    const ciphertextB64 = base64UrlEncode(ciphertext);
    const nonceB64 = base64UrlEncode(nonce);

    const observedNextClock = nextLocalClockForDevice(
      state.confirmedClocks,
      state,
      deviceSigningKeyId,
    );
    if (observedNextClock > state.localClock) {
      state.localClock = observedNextClock;
    }
    const clock = state.localClock;
    const timestamp = Date.now();

    // 2. Compute update hash (snake_case keys to match server-side JCS)
    const updateHash = computeDocumentUpdateHash({
      clock,
      signing_key_id: deviceSigningKeyId,
      document_id: documentId,
      encrypted_content: ciphertextB64,
      key_version: state.keyVersion,
      nonce: nonceB64,
      ref_snapshot_id: state.activeSnapshotId,
      timestamp,
    });
    recordSyncPerf("update_hashed", {
      documentId,
      updateHash,
      elapsedMs: performance.now() - sendStartedAt,
    });

    const writeSession = await ensureDocumentWriteSession({
      documentId,
      state,
      signingKeyId: deviceSigningKeyId,
      keyVersion: state.keyVersion,
      nextCiphertextBytes: ciphertext.length,
    });
    recordSyncPerf("update_authority_ready", {
      documentId,
      updateHash,
      elapsedMs: performance.now() - sendStartedAt,
    });
    const writeSessionCounter = writeSession.usedUpdateCount + 1;

    // 3. Build public data
    const publicData: Record<string, unknown> = {
      docId: documentId,
      signingKeyId: deviceSigningKeyId,
      keyVersion: state.keyVersion,
      refSnapshotId: state.activeSnapshotId,
      clock,
      timestamp,
      updateHash,
      ...writeSession.publicDataFields,
      writeSessionCounter,
    };
    const authorityBoundary = {
      ...writeSession.authorityBoundary,
      write_session_counter: writeSessionCounter,
    };

    // 4. Sign
    const { signature } = await worker.signDocumentUpdate({
      ciphertext: ciphertextB64,
      nonce: nonceB64,
      workspaceId: state.workspaceId,
      publicData,
      authorityBoundary,
    });
    recordSyncPerf("update_signed", {
      documentId,
      updateHash,
      elapsedMs: performance.now() - sendStartedAt,
    });
    recordSyncPerf("update_admission_built", {
      documentId,
      updateHash,
      elapsedMs: performance.now() - sendStartedAt,
    });

    // 5. Send
    const envelope = {
      ciphertext: ciphertextB64,
      nonce: nonceB64,
      signature,
      admission: documentOperationAdmissionForTransport(writeSession.admission),
      publicData,
    };
    Object.defineProperty(envelope, keyDirectoryAdvanceSymbol, {
      value: writeSession.keyDirectoryAdvance,
      enumerable: false,
    });
    writeSession.usedUpdateCount = writeSessionCounter;
    writeSession.usedCiphertextBytes += ciphertext.length;
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
    recordSyncPerf("update_push_start", {
      documentId,
      updateHash,
      elapsedMs: performance.now() - sendStartedAt,
    });

    const pushed = pushUpdate(
      documentId,
      envelope,
      (resp: unknown) => {
        // Only reset on actual server error (not timeout — timeout fires
        // even on success because server uses {:noreply} + separate event)
        if (resp !== "timeout" && state.pendingUpdateBytes) {
          state._recentSaveEvents.push({
            event: "update_push_rejected",
            at: Date.now(),
            reason: resp,
            activeSnapshotId: state.activeSnapshotId,
            hasPendingUpdateBytes: state.pendingUpdateBytes !== null,
            hasPendingUpdateEnvelope: state.pendingUpdateEnvelope !== null,
          });
          if (state._recentSaveEvents.length > 12) {
            state._recentSaveEvents.splice(0, state._recentSaveEvents.length - 12);
          }
          clearSaveAckWatchdog(state);
          handleAdmissionPushFailure(resp, state);
          handleOversizedUpdatePushFailure(resp, state);
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
  if (!deviceSigningKeyId) {
    state.sending = false;
    return;
  }
  const snapshotKeyVersion = state.pendingRotationKeyVersion ?? state.keyVersion;
  if (state.access.kind === "share") {
    await ensureSharedDekCached(state, documentId, snapshotKeyVersion);
  }

  // Encode canonical Markdown state only (V2 format).
  const yjsState = encodeCanonicalStateAsUpdateV2(state.yDoc);
  if (yjsState.length <= 2) {
    state.sending = false;
    return;
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

  // Compute ciphertext hash for proof chain
  const ciphertextHash = base64UrlEncode(await worker.blake3Hash(ciphertext));

  // Genesis snapshot: empty parent
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
    keyVersion: snapshotKeyVersion,
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
    admission: documentOperationAdmissionForTransport(admission),
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
      const shouldRefreshAdmission = handleAdmissionPushFailure(resp, state);
      state.pendingSnapshot = null;
      state.pendingSnapshotEnvelope = null;
      state.sending = false;
      if (shouldRefreshAdmission) {
        state.autoSync?.notifyLocalEdit();
      } else if (isPermanentPushFailure(resp)) {
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
  if (!deviceSigningKeyId) {
    state.sending = false;
    return;
  }
  // Encode canonical Markdown state only (V2 format).
  const yjsState = encodeCanonicalStateAsUpdateV2(state.yDoc);

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
    admission: documentOperationAdmissionForTransport(admission),
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
      const shouldRefreshAdmission = handleAdmissionPushFailure(resp, state);
      state.pendingSnapshot = null;
      state.pendingSnapshotEnvelope = null;
      state.sending = false;
      if (shouldRefreshAdmission) {
        state.autoSync?.notifyLocalEdit();
      } else if (isPermanentPushFailure(resp)) {
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

const PERMANENT_PUSH_ERRORS = new Set([
  "permission_denied",
  "device_revoked",
  "document_archived",
  "document_read_only",
  "document_write_disabled",
]);

function isPermanentPushFailure(resp: unknown): boolean {
  const reason = pushFailureReason(resp);
  return reason ? PERMANENT_PUSH_ERRORS.has(reason) : false;
}

function scheduleSnapshotRetryIfNeeded(state: DocumentState): void {
  setTimeout(() => {
    if (state.autoSync && !state.sending) {
      state.autoSync.notifyLocalEdit();
    }
  }, SNAPSHOT_RETRY_DELAY_MS);
}
