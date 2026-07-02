import { applyDeviceKeyCache } from "./inbound-signing-keys";
import { getDocumentState } from "../../model/document-state/store";
import {
  setDocumentError,
  setDocumentReadOnly,
  setDocumentSyncPaused,
} from "../../model/document-state/signals";
import type { DocumentState } from "../../model/document-state/types";
import { createInitCancelledError, isInitCancelledError } from "./bootstrap-cancel";
import {
  leaveDocument,
  isPhoenixJoinError,
  PhoenixChannelTransportError,
} from "@/shared/lib/ws/phoenix-channel";
import type { DocumentPayload } from "@/shared/lib/ws/document-payloads";
import { DocumentChannelError, DocumentSyncError, createDocumentSyncFailure } from "./error";
import {
  handleDocumentMessage,
  handleRemoteUpdate,
  handleRemoteSnapshot,
  handleRemoteWriteSession,
} from "./inbound-document";
import { startAutoSync } from "./outbound-auto-sync";
import { acquireDocumentWriterLock } from "./outbound-writer-lock";
import { triggerReconnect } from "./reconnect";
import { waitForAuthTransport } from "@/shared/lib/ws/transport-coordinator";
import { ApiError, getRateLimitRetryMs } from "@/shared/api/core";
import { isAuthUnauthorizedError } from "@/shared/lib/auth/unauthorized";
import { documentClockKey } from "@/shared/lib/anti-rollback/clock-observations";
import type { FailClosedHandler } from "./bootstrap-open";
import { runPostInitializationTasks } from "./bootstrap-post-init";
import { openInitialDocumentChannel } from "./bootstrap-open";
import { prepareInitializationSession, type PreparedInitialization } from "./bootstrap-prepare";
import { recordSyncPerf } from "./perf";
import { localDocumentClockKey, nextLocalClockForDevice } from "./local-clock";

const INITIAL_OPEN_RETRY_BASE_MS = 500;
const INITIAL_OPEN_RETRY_MAX_MS = 10_000;

function throwIfInitializationCancelled(state: DocumentState, signal: AbortSignal): void {
  if (
    signal.aborted ||
    getDocumentState(state.stateKey) !== state ||
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
  if (isAuthUnauthorizedError(error)) {
    return new DocumentSyncError("unauthorized", error.message);
  }
  if (error instanceof ApiError && error.status === 401) {
    return new DocumentSyncError("unauthorized", error.message);
  }
  if (error instanceof TypeError) {
    return new DocumentSyncError("server_unreachable", error.message);
  }
  return error;
}

function failClosedForInitialLoad(failClosed: FailClosedHandler, error: unknown): unknown {
  const normalized = normalizeDocumentSyncError(error);
  if (normalized instanceof DocumentSyncError && normalized.code === "server_unreachable") {
    failClosed("connection_error", normalized);
    return normalized;
  }

  failClosed("initial_load_failed", normalized);
  return normalized;
}

async function awaitInitialDocumentPrerequisites(
  state: DocumentState,
  preDocumentReadyPromise: PreparedInitialization["preDocumentReadyPromise"],
  deviceKeyCachePromise: PreparedInitialization["deviceKeyCachePromise"],
  failClosed?: FailClosedHandler,
): Promise<void> {
  const [preDocumentReadyOutcome, deviceKeyCacheOutcome] = await Promise.all([
    preDocumentReadyPromise,
    deviceKeyCachePromise,
  ]);
  if ("error" in preDocumentReadyOutcome) {
    throw failClosed
      ? failClosedForInitialLoad(failClosed, preDocumentReadyOutcome.error)
      : normalizeDocumentSyncError(preDocumentReadyOutcome.error);
  }
  if ("error" in deviceKeyCacheOutcome) {
    if (isInitCancelledError(deviceKeyCacheOutcome.error)) throw deviceKeyCacheOutcome.error;
    throw failClosed
      ? failClosedForInitialLoad(failClosed, deviceKeyCacheOutcome.error)
      : normalizeDocumentSyncError(deviceKeyCacheOutcome.error);
  }
  const cacheResult = deviceKeyCacheOutcome.result;
  if (cacheResult.status === "key_changed") {
    const err = new DocumentSyncError(
      "verification_failed",
      `TOFU key change detected: device ${cacheResult.warning.deviceId}`,
    );
    if (failClosed) failClosed("initial_load_failed", err);
    throw err;
  }
  applyDeviceKeyCache(state, cacheResult);
}

async function awaitInitialDocumentContentPrerequisites(
  preDocumentReadyPromise: PreparedInitialization["preDocumentReadyPromise"],
  failClosed?: FailClosedHandler,
): Promise<void> {
  const preDocumentReadyOutcome = await preDocumentReadyPromise;
  if ("error" in preDocumentReadyOutcome) {
    throw failClosed
      ? failClosedForInitialLoad(failClosed, preDocumentReadyOutcome.error)
      : normalizeDocumentSyncError(preDocumentReadyOutcome.error);
  }
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.reject(createInitCancelledError());
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timeout);
      reject(createInitCancelledError());
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function shouldSkipJoinInitialPayload(
  payload: DocumentPayload,
  state: DocumentState,
  appliedBootstrapInitialDocument: boolean,
): boolean {
  return (
    appliedBootstrapInitialDocument &&
    state.initialized &&
    payload.snapshot === null &&
    payload.updates.length === 0
  );
}

export async function doInitializeDocumentSync(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
  signal: AbortSignal,
): Promise<void> {
  const assertActive = () => throwIfInitializationCancelled(state, signal);
  setDocumentSyncPaused(state.stateKey, true);
  if (!state.initialized) state._verifiedContentPreviewReady = false;
  let localDeviceSigningKeyId: string | undefined;
  let deviceKeyCachePromise:
    | Awaited<ReturnType<typeof prepareInitializationSession>>["deviceKeyCachePromise"]
    | null = null;
  let preDocumentReadyPromise:
    | Awaited<ReturnType<typeof prepareInitializationSession>>["preDocumentReadyPromise"]
    | null = null;
  let oldDekPrimePromise:
    | Awaited<ReturnType<typeof prepareInitializationSession>>["oldDekPrimePromise"]
    | null = null;
  let buildJoinParams:
    | Awaited<ReturnType<typeof prepareInitializationSession>>["buildJoinParams"]
    | null = null;
  let documentPayload: DocumentPayload | undefined;
  let appliedDocumentPayloadForClock: DocumentPayload | undefined;
  let appliedBootstrapInitialDocument = false;
  let failClosed: FailClosedHandler | null = null;

  for (let attempt = 0; ; attempt += 1) {
    try {
      const prepared = await prepareInitializationSession(
        documentId,
        workspaceId,
        state,
        signal,
        assertActive,
      );
      localDeviceSigningKeyId = prepared.localDeviceSigningKeyId;
      deviceKeyCachePromise = prepared.deviceKeyCachePromise;
      preDocumentReadyPromise = prepared.preDocumentReadyPromise;
      oldDekPrimePromise = prepared.oldDekPrimePromise;
      buildJoinParams = prepared.buildJoinParams;
      prepared.startDeviceKeyCache?.();

      // Guard: if state was torn down during async init, leave immediately
      if (!getDocumentState(state.stateKey)) {
        leaveDocument(documentId, state.stateKey);
        return;
      }

      const bootstrapInitialDocument =
        state.access.kind === "share" && !state.initialized ? state.access.initialDocument : null;
      if (bootstrapInitialDocument) {
        const httpInitialStartedAt = performance.now();
        recordSyncPerf("initial_http_document_start", {
          documentId,
          source: "share-bootstrap",
        });
        await awaitInitialDocumentContentPrerequisites(
          preDocumentReadyPromise,
          failClosed ?? undefined,
        );
        assertActive();
        await handleDocumentMessage(bootstrapInitialDocument, state, documentId);
        appliedDocumentPayloadForClock = bootstrapInitialDocument;
        appliedBootstrapInitialDocument = true;
        if (state.access.kind === "share") state.access.initialDocument = null;
        recordSyncPerf("initial_http_document_ready", {
          documentId,
          elapsedMs: performance.now() - httpInitialStartedAt,
          source: "share-bootstrap",
        });
      }

      const joinParams = await prepared.buildJoinParams();
      assertActive();
      const opened = await openInitialDocumentChannel({
        documentId,
        workspaceId,
        state,
        signal,
        joinParams,
        localDeviceSigningKeyId,
        assertActive,
      });
      documentPayload = opened.documentPayload;
      failClosed = opened.failClosed;
      break;
    } catch (err) {
      if (isInitCancelledError(err)) throw err;
      const normalized = normalizeDocumentSyncError(err);
      const retryMs = getRateLimitRetryMs(err);
      const canRetry =
        retryMs !== null ||
        (normalized instanceof DocumentSyncError && normalized.code === "server_unreachable");
      if (!canRetry) throw err;
      await waitForAuthTransport(signal);
      assertActive();
      const retryDelay = Math.min(
        INITIAL_OPEN_RETRY_BASE_MS * 2 ** Math.min(attempt, 5),
        INITIAL_OPEN_RETRY_MAX_MS,
      );
      await sleep(Math.max(retryMs ?? 0, retryDelay) + Math.random() * 250, signal);
    }
  }
  if (
    !documentPayload ||
    !failClosed ||
    !deviceKeyCachePromise ||
    !preDocumentReadyPromise ||
    !oldDekPrimePromise ||
    !buildJoinParams
  ) {
    return;
  }
  assertActive();
  await awaitInitialDocumentPrerequisites(
    state,
    preDocumentReadyPromise,
    deviceKeyCachePromise,
    failClosed,
  );
  assertActive();
  try {
    assertActive();
    if (shouldSkipJoinInitialPayload(documentPayload, state, appliedBootstrapInitialDocument)) {
      recordSyncPerf("initial_join_delta_empty_skipped", {
        documentId,
        latestVersion: documentPayload.latestVersion,
      });
    } else {
      await handleDocumentMessage(documentPayload, state, documentId);
      appliedDocumentPayloadForClock = documentPayload;
    }
  } catch (err) {
    if (isInitCancelledError(err)) throw err;
    throw failClosedForInitialLoad(failClosed, err);
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
        localDeviceSigningKeyId,
      );
    } else if (event.type === "snapshot") {
      await handleRemoteSnapshot(
        event.payload as Parameters<typeof handleRemoteSnapshot>[0],
        state,
        documentId,
      );
    } else {
      await handleRemoteWriteSession(
        event.payload as Parameters<typeof handleRemoteWriteSession>[0],
        state,
        documentId,
      );
    }
  }
  // Guard: check again after async message processing
  if (!getDocumentState(state.stateKey)) {
    leaveDocument(documentId, state.stateKey);
    return;
  }
  if (localDeviceSigningKeyId) {
    const clockPayload = appliedDocumentPayloadForClock ?? documentPayload;
    const localClockKey = localDocumentClockKey(state, localDeviceSigningKeyId);
    let baseClock = nextLocalClockForDevice(state.confirmedClocks, state, localDeviceSigningKeyId) - 1;
    for (const update of clockPayload.updates) {
      if (
        documentClockKey(update.publicData) === localClockKey &&
        update.publicData.clock > baseClock
      ) {
        baseClock = update.publicData.clock;
      }
    }
    state.localClock = baseClock + 1;
  }
  if (documentPayload.archived) {
    setDocumentReadOnly(state.stateKey, true);
  }
  if (!state.readOnly && localDeviceSigningKeyId) {
    state.writerLockCleanup?.();
    const startWritableSync = () => {
      if (state.readOnly || state.autoSync) return;
      state.autoSync = startAutoSync(documentId, state, {
        onSaveAckTimeout: () => {
          triggerReconnect(state, documentId, workspaceId, localDeviceSigningKeyId, failClosed);
        },
      });
    };
    const writerLock = acquireDocumentWriterLock(documentId, localDeviceSigningKeyId, state, {
      onAcquired: startWritableSync,
    });
    state.writerLockCleanup = writerLock.dispose;
  }

  // 8. Start auto-sync before non-critical post-open work so the editor becomes interactive sooner.
  if (!state.readOnly && !state.autoSync) {
    state.autoSync = startAutoSync(documentId, state, {
      onSaveAckTimeout: () => {
        triggerReconnect(state, documentId, workspaceId, localDeviceSigningKeyId, failClosed);
      },
    });
  }
  void oldDekPrimePromise;
  setDocumentError(state.stateKey, null);
  setDocumentSyncPaused(state.stateKey, false);
  void runPostInitializationTasks(documentId, workspaceId, state, localDeviceSigningKeyId);
}
