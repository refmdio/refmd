import { removeAwarenessStates } from "y-protocols/awareness";
import {
  leaveDocument,
  joinDocument,
  PhoenixChannelTransportError,
} from "@/shared/lib/ws/phoenix-channel";
import type { DocumentPayload } from "@/shared/lib/ws/document-payloads";
import { createDocumentSyncFailure, DocumentSyncError } from "./error";
import { triggerReconnect } from "./reconnect";
import { setDocumentError, setDocumentSyncPaused } from "../../model/document-state/signals";
import type { DocumentState } from "../../model/document-state/types";
import { clientError } from "@/shared/lib/logger";
import { buildDocumentChannelCallbacks } from "./bootstrap-callbacks";
import { createInitCancelledError } from "./bootstrap-cancel";
import { recordSyncPerf } from "./perf";

interface PendingDocumentPromiseState {
  documentTimeout: ReturnType<typeof setTimeout> | null;
  rejectDocumentPromise: ((err: Error) => void) | null;
}

export type FailClosedHandler = (reason: string, err?: unknown) => void;

type AssertInitializationActive = () => void;

const INITIAL_DOCUMENT_EVENT_TIMEOUT_MS = 8_000;

function clearPendingDocumentPromise(pendingState: PendingDocumentPromiseState): void {
  if (pendingState.documentTimeout) clearTimeout(pendingState.documentTimeout);
  pendingState.documentTimeout = null;
  pendingState.rejectDocumentPromise = null;
}

function rejectPendingDocumentPromise(
  pendingState: PendingDocumentPromiseState,
  error: Error,
): void {
  const reject = pendingState.rejectDocumentPromise;
  clearPendingDocumentPromise(pendingState);
  reject?.(error);
}

function createDocumentPromise(
  state: DocumentState,
  pendingState: PendingDocumentPromiseState,
): Promise<DocumentPayload> {
  return new Promise<DocumentPayload>((resolve, reject) => {
    pendingState.rejectDocumentPromise = reject;
    pendingState.documentTimeout = setTimeout(() => {
      clearPendingDocumentPromise(pendingState);
      reject(new DocumentSyncError("server_unreachable", "Timeout waiting for document event"));
    }, INITIAL_DOCUMENT_EVENT_TIMEOUT_MS);
    state._onDocumentMessage = (payload: unknown) => {
      clearPendingDocumentPromise(pendingState);
      resolve(payload as DocumentPayload);
    };
  });
}

export function createFailClosedHandler(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
  signal: AbortSignal,
  pendingState: PendingDocumentPromiseState,
): FailClosedHandler {
  return (reason: string, err?: unknown) => {
    if (signal.aborted) {
      state._onDocumentMessage = null;
      rejectPendingDocumentPromise(pendingState, createInitCancelledError());
      return;
    }
    if (state.error) return;
    const failure = createDocumentSyncFailure(reason, err);
    recordSyncPerf("document_sync_fail_closed", {
      documentId,
      reason,
      error: err instanceof Error ? err.message : err === undefined ? null : String(err),
    });
    if (err) clientError("document_sync_open_failed", { reason, error: err });
    if (reason === "not_a_member" || reason === "permission_denied") {
      import("@/shared/lib/offline/storage/store").then(({ deleteOfflineKek }) =>
        deleteOfflineKek(workspaceId).catch(() => {}),
      );
    }
    state.error = reason;
    state.initialized = false;
    state._verifiedContentPreviewReady = false;
    state.initPromise = null;
    state.channel = null;
    state._onDocumentMessage = null;
    setDocumentError(state.stateKey, reason);
    setDocumentSyncPaused(state.stateKey, false);
    rejectPendingDocumentPromise(pendingState, failure);
    if (state.autoSync) {
      state.autoSync.dispose();
      state.autoSync = null;
    }
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
    state.writeSession = null;
    state.writeSessionPromise = null;
    state.writeSessionReadyAt = null;
    state.writeSessionError = null;
    leaveDocument(documentId, state.stateKey);
  };
}

export async function openInitialDocumentChannel(params: {
  documentId: string;
  workspaceId: string;
  state: DocumentState;
  signal: AbortSignal;
  joinParams: Record<string, unknown>;
  localDeviceSigningKeyId: string | undefined;
  assertActive: AssertInitializationActive;
}): Promise<{ documentPayload: DocumentPayload; failClosed: FailClosedHandler }> {
  const {
    documentId,
    workspaceId,
    state,
    signal,
    joinParams,
    localDeviceSigningKeyId,
    assertActive,
  } = params;

  const pendingState: PendingDocumentPromiseState = {
    documentTimeout: null,
    rejectDocumentPromise: null,
  };
  const documentPromise = createDocumentPromise(state, pendingState);
  void documentPromise.catch(() => {});
  const failClosed = createFailClosedHandler(documentId, workspaceId, state, signal, pendingState);
  const callbacks = buildDocumentChannelCallbacks(
    state,
    documentId,
    localDeviceSigningKeyId,
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
      onUpdateSaveFailed: (payload) => {
        if (!payload.requiresNewSnapshot) {
          state.autoSync?.notifyLocalEdit();
        }
      },
      onSyncGap: (err) => {
        void err;
        state._forceCompleteReconnect = true;
        triggerReconnect(state, documentId, workspaceId, localDeviceSigningKeyId, failClosed);
      },
      onError: (reason) => {
        if (
          reason === "document_not_found" ||
          reason === "document_error" ||
          reason === "connection_cap_evict"
        ) {
          failClosed(String(reason));
        } else if (state.initialized) {
          triggerReconnect(state, documentId, workspaceId, localDeviceSigningKeyId, failClosed);
        } else {
          rejectPendingDocumentPromise(
            pendingState,
            new PhoenixChannelTransportError(
              "disconnected_before_document",
              "Channel errored before document received",
            ),
          );
        }
      },
      onClose: () => {
        if (state.initialized) {
          triggerReconnect(state, documentId, workspaceId, localDeviceSigningKeyId, failClosed);
        } else {
          rejectPendingDocumentPromise(
            pendingState,
            new PhoenixChannelTransportError(
              "disconnected_before_document",
              "Channel closed before document received",
            ),
          );
        }
      },
    },
  );

  let channel;
  try {
    assertActive();
    channel = await joinDocument(
      documentId,
      joinParams,
      callbacks,
      state.stateKey,
      state.access.kind === "share" ? "share" : "user",
    );
  } catch (err) {
    clearPendingDocumentPromise(pendingState);
    state._onDocumentMessage = null;
    throw err;
  }

  state.channel = channel;
  assertActive();

  let documentPayload;
  try {
    documentPayload = await documentPromise;
  } catch (err) {
    clearPendingDocumentPromise(pendingState);
    state._onDocumentMessage = null;
    state.channel = null;
    leaveDocument(documentId, state.stateKey);
    throw err;
  }
  assertActive();

  return { documentPayload, failClosed };
}
