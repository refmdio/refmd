import { removeAwarenessStates } from "y-protocols/awareness";
import { leaveDocument, joinDocument } from "@/shared/lib/ws/phoenix-channel";
import type { DocumentPayload } from "@/shared/lib/ws/document-payloads";
import { createDocumentSyncFailure, DocumentSyncError } from "../error";
import { triggerReconnect } from "../reconnect/reconnect";
import { setDocumentError } from "../../../model/document-state/signals";
import type { DocumentState } from "../../../model/document-state/types";
import { buildDocumentChannelCallbacks } from "./callbacks";
import { createInitCancelledError } from "./cancel";

interface PendingDocumentPromiseState {
  documentTimeout: ReturnType<typeof setTimeout> | null;
  rejectDocumentPromise: ((err: Error) => void) | null;
}

export type FailClosedHandler = (reason: string, err?: unknown) => void;

type AssertInitializationActive = () => void;

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

export function createFailClosedHandler(
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
    if (reason === "not_a_member" || reason === "permission_denied") {
      import("@/shared/lib/offline/storage/store").then(({ deleteOfflineKek }) =>
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

export async function openInitialDocumentChannel(params: {
  documentId: string;
  workspaceId: string;
  state: DocumentState;
  signal: AbortSignal;
  joinParams: Record<string, unknown>;
  localDeviceSigningPubKey: string | undefined;
  assertActive: AssertInitializationActive;
}): Promise<{ documentPayload: DocumentPayload; failClosed: FailClosedHandler }> {
  const {
    documentId,
    workspaceId,
    state,
    signal,
    joinParams,
    localDeviceSigningPubKey,
    assertActive,
  } = params;

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
      onUpdateSaveFailed: (payload) => {
        if (!payload.requiresNewSnapshot) {
          triggerReconnect(state, documentId, workspaceId, localDeviceSigningPubKey, failClosed);
        }
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
    assertActive();
    channel = await joinDocument(documentId, joinParams, callbacks);
  } catch (err) {
    if (pendingState.documentTimeout) clearTimeout(pendingState.documentTimeout);
    state._onDocumentMessage = null;
    throw err;
  }

  state.channel = channel;
  assertActive();

  const documentPayload = await documentPromise;
  assertActive();

  return { documentPayload, failClosed };
}
