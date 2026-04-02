import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { resolveActiveKek, resolveKekByVersion } from "@/shared/lib/crypto/kek-resolver";
import { encryptionApi } from "@/shared/api/encryption";
import { getPopHeaders } from "@/shared/lib/pop";
import { applyDeviceKeyCache, buildDeviceKeyCaches } from "./document-verification";
import { getDocumentState, setDocumentError, type DocumentState } from "./document-state-cache";
import {
  joinDocument,
  leaveDocument,
  isPhoenixJoinError,
  PhoenixChannelTransportError,
} from "@/shared/lib/ws/phoenix-channel";
import type { DocumentPayload } from "@/shared/lib/ws/document-payloads";
import {
  DocumentChannelError,
  DocumentSyncError,
  createDocumentSyncFailure,
} from "./document-sync-error";
import { handleDocumentMessage, handleRemoteUpdate, handleRemoteSnapshot } from "./ws-handlers";
import { startAutoSync } from "./auto-sync";
import { deviceState, getKekResolverSession } from "@/entities/session";
import { removeAwarenessStates } from "y-protocols/awareness";
import { triggerReconnect } from "./ws-reconnect";
import { completeDekRotationIfNeeded } from "./document-sync-dek-rotation";
import { buildDocumentChannelCallbacks } from "./document-channel-callbacks";
import { primeHistoricalDeks, runPostInitializationTasks } from "./document-sync-post-init";
interface PendingDocumentPromiseState {
  documentTimeout: ReturnType<typeof setTimeout> | null;
  rejectDocumentPromise: ((err: Error) => void) | null;
}
type FailClosedHandler = (reason: string, err?: unknown) => void;
function createInitCancelledError(): Error {
  const error = new Error("init_cancelled");
  error.name = "AbortError";
  return error;
}
export function isInitCancelledError(error: unknown): boolean {
  return error instanceof Error && error.name === "AbortError";
}
function throwIfInitializationCancelled(
  documentId: string,
  state: DocumentState,
  signal: AbortSignal,
): void {
  if (
    signal.aborted ||
    getDocumentState(documentId) !== state ||
    (state.refCount <= 0 && !state._headlessSync)
  ) {
    throw createInitCancelledError();
  }
}
export function normalizeDocumentSyncError(error: unknown): unknown {
  if (error instanceof DocumentSyncError || error instanceof DocumentChannelError) {
    return error;
  }
  if (isPhoenixJoinError(error)) {
    const reason = error.joinErrorResp?.reason;
    if (typeof reason === "string") {
      return createDocumentSyncFailure(reason, error);
    }
  }
  if (error instanceof PhoenixChannelTransportError) {
    return new DocumentSyncError("server_unreachable", error.message);
  }
  if (error instanceof TypeError) {
    return new DocumentSyncError("server_unreachable", error.message);
  }
  return error;
}
function createDocumentPromise(
  state: DocumentState,
  pendingState: PendingDocumentPromiseState,
): Promise<DocumentPayload> {
  return new Promise<DocumentPayload>((resolve, reject) => {
    pendingState.rejectDocumentPromise = reject;
    pendingState.documentTimeout = setTimeout(() => {
      reject(new DocumentSyncError("server_unreachable", "Timeout waiting for document event"));
    }, 30000);
    state._onDocumentMessage = (payload: unknown) => {
      clearTimeout(pendingState.documentTimeout!);
      pendingState.documentTimeout = null;
      pendingState.rejectDocumentPromise = null;
      resolve(payload as DocumentPayload);
    };
  });
}
function createFailClosedHandler(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
  signal: AbortSignal,
  pendingState: PendingDocumentPromiseState,
): FailClosedHandler {
  return (reason: string, err?: unknown) => {
    if (signal.aborted) {
      if (pendingState.documentTimeout) clearTimeout(pendingState.documentTimeout);
      if (pendingState.rejectDocumentPromise) {
        pendingState.rejectDocumentPromise(createInitCancelledError());
      }
      return;
    }
    if (state.error) return;
    const failure = createDocumentSyncFailure(reason, err);
    if (err) console.error(`[ws] ${reason}:`, err);
    // On workspace access loss, purge KEK cache (design: keep DEK for local read-only)
    if (reason === "not_a_member" || reason === "permission_denied") {
      import("@/shared/lib/offline/offline-store").then(({ deleteOfflineKek }) =>
        deleteOfflineKek(workspaceId).catch(() => {}),
      );
    }
    state.error = reason;
    state.initialized = false;
    state.initPromise = null;
    state.channel = null;
    setDocumentError(documentId, reason);
    if (pendingState.documentTimeout) clearTimeout(pendingState.documentTimeout);
    if (pendingState.rejectDocumentPromise) {
      pendingState.rejectDocumentPromise(failure);
    }
    if (state.autoSync) {
      state.autoSync.dispose();
      state.autoSync = null;
    }
    // Clear all awareness states (local + remote) to prevent stale avatars
    const allClientIds: number[] = [];
    state.awareness.getStates().forEach((_, clientId) => allClientIds.push(clientId));
    if (allClientIds.length > 0) {
      removeAwarenessStates(state.awareness, allClientIds, "fail-closed");
    }
    state.awarenessClientOwners.clear();
    state.awarenessRelayCleanup?.();
    state.awarenessRelayCleanup = null;
    state.ephemeralSession = null;
    state.channel = null;
    state.sending = false;
    state.pendingSnapshot = null;
    state.pendingSnapshotEnvelope = null;
    state.pendingUpdateBytes = null;
    state.pendingUpdateEnvelope = null;
    leaveDocument(documentId);
  };
}
export async function doInitializeDocumentSync(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
  signal: AbortSignal,
): Promise<void> {
  const worker = getCryptoWorker();
  const device = deviceState();
  if (!device) throw new Error("Device state not available");
  const localDeviceSigningPubKey = device.deviceSigningPublic
    ? base64UrlEncode(device.deviceSigningPublic)
    : undefined;
  throwIfInitializationCancelled(documentId, state, signal);
  const activeKekPromise = resolveActiveKek(workspaceId, getKekResolverSession(), signal);
  const documentKeysPromise = encryptionApi.getDocumentKeys(documentId, { signal });
  const deviceKeyCachePromise = buildDeviceKeyCaches(workspaceId, signal)
    .then((result) => ({ result }))
    .catch((error) => ({ error }));
  const existingPinPromise = import("@/shared/lib/anti-rollback/document-state-pins").then(
    ({ getDocumentStatePin }) => getDocumentStatePin(documentId).catch(() => null),
  );
  const [{ kekVersion: activeKekVersion }, keysResponse] = await Promise.all([
    activeKekPromise,
    documentKeysPromise,
  ]);
  throwIfInitializationCancelled(documentId, state, signal);
  const keys = keysResponse.keys;
  const activeKey = keys.find((key) => key.is_active);
  if (!activeKey) {
    throw new Error("No active DEK found for document");
  }
  // Resolve KEK for active DEK if it was wrapped with a different KEK version
  if (activeKey.kek_version !== activeKekVersion) {
    await resolveKekByVersion(workspaceId, activeKey.kek_version, getKekResolverSession(), signal);
    throwIfInitializationCancelled(documentId, state, signal);
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
  const oldDekPrimePromise = primeHistoricalDeks(
    documentId,
    workspaceId,
    keys,
    activeKekVersion,
    activeKey.key_version,
    signal,
  );
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
  }, 30000);
  // 4. PoP for Channel join
  const [popHeaders, existingPin] = await Promise.all([
    getPopHeaders(undefined, signal),
    existingPinPromise,
  ]);
  throwIfInitializationCancelled(documentId, state, signal);
  // Use delta mode only if Y.Doc already has base state AND lastSavedState is available.
  // lastSavedState is required for server-relative diff computation on reconnect.
  // After cache recovery, lastSavedState is null — force complete mode so
  // handleDocumentMessage can rebuild it from the full server response.
  const knownSnapshotId = state.activeSnapshotId ?? null;
  const pinSnapshotId = existingPin?.latestSnapshotId ?? null;
  const useDelta = !!knownSnapshotId && !!state.lastSavedState;
  const joinParams: Record<string, unknown> = {
    pop_challenge: popHeaders["X-PoP-Challenge"],
    pop_signature: popHeaders["X-PoP-Signature"],
    mode: useDelta ? "delta" : "complete",
  };
  state._lastJoinMode = useDelta ? "delta" : "complete";
  // Always send knownSnapshotId when available (from state or pin) for proof chain verification
  const effectiveKnownSnapshot = knownSnapshotId ?? pinSnapshotId;
  if (effectiveKnownSnapshot) {
    joinParams.knownSnapshotId = effectiveKnownSnapshot;
  }
  if (useDelta) {
    const clocks =
      Object.keys(state.confirmedClocks).length > 0
        ? state.confirmedClocks
        : (existingPin?.perDeviceMaxClocks ?? {});
    joinParams.knownSnapshotUpdateClocks = { ...clocks };
  }
  const pendingState: PendingDocumentPromiseState = {
    documentTimeout: null,
    rejectDocumentPromise: null,
  };
  const documentPromise = createDocumentPromise(state, pendingState);
  const failClosed = createFailClosedHandler(documentId, workspaceId, state, signal, pendingState);
  const callbacks = buildDocumentChannelCallbacks(
    state,
    documentId,
    localDeviceSigningPubKey,
    failClosed,
    {
      onDocument: (payload) => {
        if (state._onDocumentMessage) {
          state._onDocumentMessage(payload);
          state._onDocumentMessage = null;
        }
      },
      onUnauthorized: () => {
        failClosed("unauthorized");
      },
      onError: (reason) => {
        if (
          reason === "document_not_found" ||
          reason === "document_error" ||
          reason === "connection_cap_evict"
        ) {
          failClosed(String(reason));
        } else if (state.initialized) {
          triggerReconnect(state, documentId, workspaceId, localDeviceSigningPubKey, failClosed);
        } else {
          failClosed(String(reason) || "connection_error");
        }
      },
      onClose: () => {
        if (state.initialized) {
          triggerReconnect(state, documentId, workspaceId, localDeviceSigningPubKey, failClosed);
        } else {
          failClosed("disconnected");
        }
      },
    },
  );
  let channel;
  try {
    throwIfInitializationCancelled(documentId, state, signal);
    channel = await joinDocument(documentId, joinParams, callbacks);
  } catch (err) {
    if (pendingState.documentTimeout) clearTimeout(pendingState.documentTimeout);
    state._onDocumentMessage = null;
    throw err;
  }
  state.channel = channel;
  throwIfInitializationCancelled(documentId, state, signal);
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
    if (isInitCancelledError(err)) throw err;
    failClosed("initial_load_failed", err);
    throw err;
  }
  throwIfInitializationCancelled(documentId, state, signal);
  const deviceKeyCacheOutcome = await deviceKeyCachePromise;
  throwIfInitializationCancelled(documentId, state, signal);
  if ("error" in deviceKeyCacheOutcome) {
    if (isInitCancelledError(deviceKeyCacheOutcome.error)) throw deviceKeyCacheOutcome.error;
    failClosed("initial_load_failed", deviceKeyCacheOutcome.error);
    throw deviceKeyCacheOutcome.error;
  }
  const cacheResult = deviceKeyCacheOutcome.result;
  if (cacheResult.status === "key_changed") {
    const err = new DocumentSyncError(
      "verification_failed",
      `TOFU key change detected: device ${cacheResult.warning.deviceId}`,
    );
    failClosed("initial_load_failed", err);
    throw err;
  }
  applyDeviceKeyCache(state, cacheResult);
  try {
    throwIfInitializationCancelled(documentId, state, signal);
    await handleDocumentMessage(documentPayload, state, documentId);
  } catch (err) {
    if (isInitCancelledError(err)) throw err;
    failClosed("initial_load_failed", err);
    throw err;
  }
  // Drain events queued during async document processing
  const queued = state._pendingRemoteEvents.splice(0);
  for (const event of queued) {
    throwIfInitializationCancelled(documentId, state, signal);
    if (event.type === "update") {
      await handleRemoteUpdate(
        event.payload as Parameters<typeof handleRemoteUpdate>[0],
        state,
        documentId,
        localDeviceSigningPubKey,
      );
    } else {
      await handleRemoteSnapshot(
        event.payload as Parameters<typeof handleRemoteSnapshot>[0],
        state,
        documentId,
      );
    }
  }
  // Guard: check again after async message processing
  if (!getDocumentState(documentId)) {
    leaveDocument(documentId);
    return;
  }
  // 7. Derive localClock per design: nextClockの導出
  // Step 1: baseClock from parentSnapshotUpdateClocks
  //   - Snapshot received: use snapshot.publicData.parentSnapshotUpdateClocks
  //   - snapshot: null (same snapshot delta): use previously known clocks (sent as join params)
  // Step 2: advance from updates[] for this device
  if (localDeviceSigningPubKey) {
    const parentClocks =
      documentPayload.snapshot?.publicData?.parentSnapshotUpdateClocks ?? state.confirmedClocks;
    let baseClock = parentClocks[localDeviceSigningPubKey] ?? -1;
    for (const update of documentPayload.updates) {
      if (
        update.publicData.signingPubKey === localDeviceSigningPubKey &&
        update.publicData.clock > baseClock
      ) {
        baseClock = update.publicData.clock;
      }
    }
    state.localClock = baseClock + 1;
  }
  // 8. Start auto-sync before non-critical post-open work so the editor becomes interactive sooner.
  state.autoSync = startAutoSync(documentId, state);
  state.autoSync.notifyLocalEdit();
  void oldDekPrimePromise;
  void runPostInitializationTasks(documentId, workspaceId, state, localDeviceSigningPubKey);
}
