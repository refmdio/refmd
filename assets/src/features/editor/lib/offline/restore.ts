import * as Y from "yjs";
import type { DocumentState } from "../../model/document-state/types";
import { initializeDocumentSync } from "../sync/initialize";
import { startAutoSync } from "../sync/outbound-auto-sync";
import { setDocumentSyncPaused } from "../../model/document-state/signals";
import { recoverDocumentFromCache } from "@/shared/lib/offline/cache/manager/recover";
import { startPeriodicFlush } from "@/shared/lib/offline/cache/manager/write";
import {
  isNetworkOnline,
  onOfflineModeChange,
  setWsConnected,
} from "@/shared/lib/offline/offline-state";
import { getOfflineCreated } from "@/shared/lib/offline/storage/store";
import { isSocketConnected } from "@/shared/lib/ws/phoenix-channel";
import { DocumentSyncError } from "../sync/error";

function teardownOfflineRuntime(state: DocumentState): void {
  if (state.autoSync) {
    state.autoSync.dispose();
    state.autoSync = null;
  }
  if (state.offlineFlushCleanup) {
    state.offlineFlushCleanup();
    state.offlineFlushCleanup = null;
  }
  if (state.offlineResumeCleanup) {
    state.offlineResumeCleanup();
    state.offlineResumeCleanup = null;
  }
}

async function resumeDocumentFromServer(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<void> {
  teardownOfflineRuntime(state);
  state.loadedFromOfflineCache = false;
  state.initialized = false;
  state.initPromise = null;
  state.error = null;

  try {
    state.initPromise = initializeDocumentSync(documentId, workspaceId, state);
    await state.initPromise;
    return;
  } catch (err) {
    state.initPromise = null;

    if (err instanceof DocumentSyncError && err.code === "unauthorized") {
      const { requestReauth } = await import("../../model/document-state/signals");
      await requestReauth(state.stateKey);

      try {
        state.initPromise = initializeDocumentSync(documentId, workspaceId, state);
        await state.initPromise;
        return;
      } catch (retryErr) {
        state.initPromise = null;
        if (retryErr instanceof DocumentSyncError && retryErr.code === "server_unreachable") {
          activateOfflineEditingSession(documentId, workspaceId, state, true);
          return;
        }
        state.error = retryErr instanceof Error ? retryErr.message : String(retryErr);
        return;
      }
    }

    if (err instanceof DocumentSyncError && err.code === "server_unreachable") {
      activateOfflineEditingSession(documentId, workspaceId, state, true);
      return;
    }

    state.error = err instanceof Error ? err.message : String(err);
  }
}

function activateOfflineEditingSession(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
  forceOfflineMode = false,
): void {
  let resumeDisposed = false;
  let resumeWaitTimer: ReturnType<typeof setTimeout> | null = null;
  const clearResumeWaitTimer = () => {
    if (!resumeWaitTimer) return;
    clearTimeout(resumeWaitTimer);
    resumeWaitTimer = null;
  };
  const resumeWhenServerReady = () => {
    if (resumeDisposed || !state.loadedFromOfflineCache) return;
    clearResumeWaitTimer();
    void getOfflineCreated(documentId)
      .then((offlineCreated) => {
        if (resumeDisposed || !state.loadedFromOfflineCache) return;
        if (offlineCreated?.syncBlockedReason) {
          state.readOnly = true;
          return;
        }
        if (offlineCreated) {
          void import("./sync-created")
            .then(({ syncOfflineCreatedDocuments }) => syncOfflineCreatedDocuments(workspaceId))
            .catch(() => {})
            .finally(() => {
              if (!resumeDisposed && state.loadedFromOfflineCache) {
                resumeWaitTimer = setTimeout(resumeWhenServerReady, 1_000);
              }
            });
          return;
        }
        void resumeDocumentFromServer(documentId, workspaceId, state);
      })
      .catch(() => {
        if (resumeDisposed || !state.loadedFromOfflineCache) return;
        void resumeDocumentFromServer(documentId, workspaceId, state);
      });
  };
  state.initialized = true;
  setDocumentSyncPaused(state.stateKey, false);
  state.loadedFromOfflineCache = true;
  state.error = null;

  if (forceOfflineMode || !isSocketConnected()) {
    setWsConnected(false);
  }

  state.autoSync = startAutoSync(documentId, state);
  state.offlineFlushCleanup = startPeriodicFlush(documentId, workspaceId, state);
  const stopOfflineWatch = onOfflineModeChange((isOffline) => {
    if (!isOffline && state.loadedFromOfflineCache) {
      resumeWhenServerReady();
    }
  });
  if (!forceOfflineMode && isNetworkOnline()) {
    resumeWhenServerReady();
  }
  state.offlineResumeCleanup = () => {
    resumeDisposed = true;
    clearResumeWaitTimer();
    stopOfflineWatch();
  };
}

export async function restoreDocumentStateFromCache(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<boolean> {
  if (state.access.kind === "share") return false;

  const recovered = await recoverDocumentFromCache(documentId);
  if (!recovered) return false;

  teardownOfflineRuntime(state);

  const recoveredState = Y.encodeStateAsUpdate(recovered.yDoc);
  Y.applyUpdate(state.yDoc, recoveredState, "remote");
  recovered.yDoc.destroy();

  state.activeSnapshotId = recovered.confirmedSnapshotId || null;
  state.confirmedClocks = recovered.confirmedClocks;
  state.knownClocks = { ...recovered.confirmedClocks };
  state.latestVersion = recovered.confirmedVersion;
  state.keyVersion = recovered.keyVersion;
  state.dekResolved = true;
  state.workspaceId = workspaceId;
  state.error = null;
  state.readOnly = false;
  state.initialized = false;
  state.loadedFromOfflineCache = false;
  state.lastSavedState = recovered.confirmedBaseState ?? null;
  state._cachedConfirmedStateVector = recovered.confirmedStateVector ?? null;

  // Restore proof chain state from persisted pin for reconnect validation
  const { getDocumentStatePin, hasCompleteSnapshotPin } =
    await import("@/shared/lib/anti-rollback/document-state-pins");
  const pin = await getDocumentStatePin(documentId).catch(() => null);
  if (hasCompleteSnapshotPin(pin) && pin.latestSnapshotId === state.activeSnapshotId) {
    state.snapshotProofHash = pin.latestSnapshotProofHash;
    state.snapshotCiphertextHash = pin.latestSnapshotCiphertextHash;
  } else {
    state.snapshotProofHash = "";
    state.snapshotCiphertextHash = "";
  }

  return true;
}

export async function initializeDocumentFromCache(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<boolean> {
  const restored = await restoreDocumentStateFromCache(documentId, workspaceId, state);
  if (!restored) return false;

  activateOfflineEditingSession(documentId, workspaceId, state);
  return true;
}
