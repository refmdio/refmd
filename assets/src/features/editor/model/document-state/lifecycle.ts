import { removeAwarenessStates } from "y-protocols/awareness";
import { flushDocumentCache } from "@/shared/lib/offline/cache/manager/write";
import { leaveDocument } from "@/shared/lib/ws/phoenix-channel";
import { clearDocumentSignals } from "./signals";
import { documentStateEvictionDelayMs, documentStates } from "./registry";
import type { DocumentState, TeardownOptions } from "./types";

function teardownState(
  stateKey: string,
  state: DocumentState,
  options: TeardownOptions = {},
): void {
  const { flushCache = true } = options;
  state._initAbortController?.abort();
  state._initAbortController = null;
  if (flushCache && state.access.kind !== "share") {
    flushDocumentCache(state.documentId, state.workspaceId, state);
  }
  if (state.offlineFlushCleanup) {
    state.offlineFlushCleanup();
    state.offlineFlushCleanup = null;
  }
  if (state.offlineResumeCleanup) {
    state.offlineResumeCleanup();
    state.offlineResumeCleanup = null;
  }
  if (state.autoSync) {
    state.autoSync.dispose();
    state.autoSync = null;
  }
  state.writerLockCleanup?.();
  state.writerLockCleanup = null;
  if (state.pendingSaveTimeout) {
    clearTimeout(state.pendingSaveTimeout);
    state.pendingSaveTimeout = null;
    state._pendingSaveWatchdogKind = null;
    state._pendingSaveWatchdogStartedAt = null;
  }
  if (state._syncGapTimer) {
    clearTimeout(state._syncGapTimer);
    state._syncGapTimer = null;
  }
  if (state._reconnectTimer) {
    clearTimeout(state._reconnectTimer);
    state._reconnectTimer = null;
  }
  state._onRecoverableSyncGap = null;
  for (const resolve of state._reauthResolvers) resolve();
  state._reauthResolvers = [];
  documentStates.delete(stateKey);
  clearDocumentSignals(stateKey);
  removeAwarenessStates(state.awareness, [state.awareness.clientID], "local");
  state.awarenessRelayCleanup?.();
  state.awarenessRelayCleanup = null;
  state.ephemeralSession = null;
  leaveDocument(state.documentId, state.stateKey);
  state.channel = null;
  state.awareness.destroy();
  state.yDoc.destroy();
}

export function releaseDocumentState(stateKey: string): void {
  const state = documentStates.get(stateKey);
  if (!state) return;
  state.refCount--;
  if (state.refCount <= 0) {
    if (state.initPromise && !state.initialized && !state._headlessSync) {
      void state.initPromise.catch(() => {});
      state._initAbortController?.abort();
      state._initAbortController = null;
      leaveDocument(state.documentId, state.stateKey);
      state.channel = null;
    }
    setTimeout(() => {
      const current = documentStates.get(stateKey);
      if (current && current.refCount <= 0) {
        teardownState(stateKey, current);
      }
    }, documentStateEvictionDelayMs);
  }
}

export function clearAllDocumentStates(options: TeardownOptions = {}): void {
  for (const [stateKey, state] of documentStates) {
    teardownState(stateKey, state, options);
  }
}

export function resetDocumentState(stateKey: string, options: TeardownOptions = {}): void {
  const state = documentStates.get(stateKey);
  if (!state) return;
  teardownState(stateKey, state, options);
}

export function acquireYDoc(stateKey: string): {
  yDoc: DocumentState["yDoc"];
  awareness: DocumentState["awareness"];
} {
  const state = documentStates.get(stateKey);
  if (!state) {
    throw new Error(
      `acquireYDoc: no DocumentState for ${stateKey}. Call acquireDocumentState first.`,
    );
  }
  state.refCount++;
  return { yDoc: state.yDoc, awareness: state.awareness };
}

export function releaseYDoc(stateKey: string): void {
  releaseDocumentState(stateKey);
}
