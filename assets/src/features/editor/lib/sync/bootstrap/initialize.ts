import { applyDeviceKeyCache } from "../inbound/signing-keys";
import { getDocumentState } from "../../../model/document-state/store";
import type { DocumentState } from "../../../model/document-state/types";
import { createInitCancelledError, isInitCancelledError } from "./cancel";
import {
  leaveDocument,
  isPhoenixJoinError,
  PhoenixChannelTransportError,
} from "@/shared/lib/ws/phoenix-channel";
import { DocumentChannelError, DocumentSyncError, createDocumentSyncFailure } from "../error";
import {
  handleDocumentMessage,
  handleRemoteUpdate,
  handleRemoteSnapshot,
} from "../inbound/document";
import { startAutoSync } from "../outbound/auto-sync";
import type { FailClosedHandler } from "./open";
import { runPostInitializationTasks } from "./post-init";
import { openInitialDocumentChannel } from "./open";
import { prepareInitializationSession } from "./prepare";

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

export async function doInitializeDocumentSync(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
  signal: AbortSignal,
): Promise<void> {
  const assertActive = () => throwIfInitializationCancelled(documentId, state, signal);
  const { localDeviceSigningPubKey, deviceKeyCachePromise, oldDekPrimePromise, joinParams } =
    await prepareInitializationSession(documentId, workspaceId, state, signal, assertActive);

  // Guard: if state was torn down during async init, leave immediately
  if (!getDocumentState(documentId)) {
    leaveDocument(documentId);
    return;
  }

  let documentPayload;
  let failClosed: FailClosedHandler;
  try {
    const opened = await openInitialDocumentChannel({
      documentId,
      workspaceId,
      state,
      signal,
      joinParams,
      localDeviceSigningPubKey,
      assertActive,
    });
    documentPayload = opened.documentPayload;
    failClosed = opened.failClosed;
  } catch (err) {
    if (isInitCancelledError(err)) throw err;
    throw err;
  }
  assertActive();
  const deviceKeyCacheOutcome = await deviceKeyCachePromise;
  assertActive();
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
    assertActive();
    await handleDocumentMessage(documentPayload, state, documentId);
  } catch (err) {
    if (isInitCancelledError(err)) throw err;
    failClosed("initial_load_failed", err);
    throw err;
  }
  // Drain events queued during async document processing
  const queued = state._pendingRemoteEvents.splice(0);
  for (const event of queued) {
    assertActive();
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
  void oldDekPrimePromise;
  void runPostInitializationTasks(documentId, workspaceId, state, localDeviceSigningPubKey);
}
