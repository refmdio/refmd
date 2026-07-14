import {
  acquireDocumentState,
  getDocumentState,
  waitForDocumentVerifiedContentPreview,
} from "../../model/document-state/store";
import { releaseDocumentState } from "../../model/document-state/lifecycle";
import { initializeDocumentSync } from "./initialize";
import { recordSyncPerf } from "./perf";

export function primeDocumentSync(
  documentId: string,
  workspaceId: string,
  stateKey = documentId,
): Promise<void> {
  return (async () => {
    recordSyncPerf("document_sync_prime_started", { documentId, stateKey, workspaceId });
    await acquireDocumentState(documentId, workspaceId, stateKey);
    const state = getDocumentState(stateKey);
    if (!state) {
      releaseDocumentState(stateKey);
      return;
    }

    const previousHeadlessSync = state._headlessSync;
    state._headlessSync = true;
    try {
      if (!state.initialized && !state.initPromise && !state.error) {
        state.initPromise = initializeDocumentSync(documentId, workspaceId, state);
      }
      if (state.initPromise) {
        await state.initPromise.catch((error) => {
          recordPrimeFailure(documentId, stateKey, error);
        });
      }
      recordSyncPerf("document_sync_prime_ready", {
        documentId,
        initialized: state.initialized,
        stateKey,
      });
    } finally {
      state._headlessSync = previousHeadlessSync;
      releaseDocumentState(stateKey);
    }
  })();
}

export function primeDocumentContentPreview(
  documentId: string,
  workspaceId: string,
  stateKey = documentId,
): Promise<void> {
  return (async () => {
    recordSyncPerf("document_sync_prime_content_started", { documentId, stateKey, workspaceId });
    await acquireDocumentState(documentId, workspaceId, stateKey);
    const state = getDocumentState(stateKey);
    if (!state) {
      releaseDocumentState(stateKey);
      return;
    }

    const previousHeadlessSync = state._headlessSync;
    state._headlessSync = true;
    let keepAliveReleased = false;
    const releaseKeepAlive = () => {
      if (keepAliveReleased) return;
      keepAliveReleased = true;
      state._headlessSync = previousHeadlessSync;
      releaseDocumentState(stateKey);
    };

    try {
      if (!state.initialized && !state.initPromise && !state.error) {
        state.initPromise = initializeDocumentSync(documentId, workspaceId, state);
      }
      const initPromise = state.initPromise;
      if (!initPromise || state.initialized || state._verifiedContentPreviewReady) {
        recordSyncPerf("document_sync_prime_content_ready", {
          documentId,
          initialized: state.initialized,
          stateKey,
        });
        releaseKeepAlive();
        return;
      }

      void initPromise
        .catch((error) => {
          recordPrimeFailure(documentId, stateKey, error);
        })
        .finally(() => {
          recordSyncPerf("document_sync_prime_ready", {
            documentId,
            initialized: state.initialized,
            stateKey,
          });
          releaseKeepAlive();
        });

      await waitForDocumentVerifiedContentPreview(stateKey, initPromise);
      recordSyncPerf("document_sync_prime_content_ready", {
        documentId,
        initialized: state.initialized,
        stateKey,
      });
    } catch (error) {
      releaseKeepAlive();
      throw error;
    }
  })();
}

function recordPrimeFailure(documentId: string, stateKey: string, error: unknown): void {
  recordSyncPerf("document_sync_prime_failed", {
    documentId,
    error: error instanceof Error ? error.message : String(error),
    stateKey,
  });
}
