import { removeAwarenessStates } from "y-protocols/awareness";
import { flushDocumentCache } from "@/shared/lib/offline/cache/manager/write";
import { leaveDocument } from "@/shared/lib/ws/phoenix-channel";
import { clearDocumentSignals } from "./signals";
import { documentStateEvictionDelayMs, documentStates } from "./registry";
import type { DocumentState, TeardownOptions } from "./types";

function teardownState(
  documentId: string,
  state: DocumentState,
  options: TeardownOptions = {},
): void {
  const { flushCache = true } = options;
  state._initAbortController?.abort();
  state._initAbortController = null;
  if (flushCache) {
    flushDocumentCache(documentId, state.workspaceId, state);
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
  for (const resolve of state._reauthResolvers) resolve();
  state._reauthResolvers = [];
  for (const resolve of state._rollbackResolvers) resolve();
  state._rollbackResolvers = [];
  documentStates.delete(documentId);
  clearDocumentSignals(documentId);
  removeAwarenessStates(state.awareness, [state.awareness.clientID], "local");
  state.awarenessRelayCleanup?.();
  state.awarenessRelayCleanup = null;
  state.ephemeralSession = null;
  leaveDocument(documentId);
  state.channel = null;
  state.awareness.destroy();
  state.yDoc.destroy();
}

export function releaseDocumentState(documentId: string): void {
  const state = documentStates.get(documentId);
  if (!state) return;
  state.refCount--;
  if (state.refCount <= 0) {
    if (state.initPromise && !state.initialized && !state._headlessSync) {
      void state.initPromise.catch(() => {});
      state._initAbortController?.abort();
      state._initAbortController = null;
      leaveDocument(documentId);
      state.channel = null;
    }
    setTimeout(() => {
      const current = documentStates.get(documentId);
      if (current && current.refCount <= 0) {
        teardownState(documentId, current);
      }
    }, documentStateEvictionDelayMs);
  }
}

export function clearAllDocumentStates(options: TeardownOptions = {}): void {
  for (const [documentId, state] of documentStates) {
    teardownState(documentId, state, options);
  }
}

export function acquireYDoc(documentId: string): {
  yDoc: DocumentState["yDoc"];
  awareness: DocumentState["awareness"];
} {
  const state = documentStates.get(documentId);
  if (!state) {
    throw new Error(
      `acquireYDoc: no DocumentState for ${documentId}. Call acquireDocumentState first.`,
    );
  }
  state.refCount++;
  return { yDoc: state.yDoc, awareness: state.awareness };
}

export function releaseYDoc(documentId: string): void {
  releaseDocumentState(documentId);
}
